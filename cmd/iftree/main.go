package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	netflow_collector "github.com/nxsre/netflow-collector"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/node_exporter/collector"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/nerdctl/pkg/rootlessutil"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/t1anz0ng/iftree/pkg/netutil"
	"github.com/t1anz0ng/iftree/pkg/types"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

var (
	hostname, _ = os.Hostname()
	debug       = pflag.BoolP("debug", "d", false, "print debug message")

	help        = pflag.BoolP("help", "h", false, "")
	ident       = pflag.StringP("ident", "i", hostname, "device id")
	pushgateway = pflag.StringP("pushgateway", "p", "", "pushgateway address")
	listen      = pflag.StringP("listen", "l", "127.0.0.1:9222", "listen address")

	netflowCols = NewCollectors()
	lock        sync.RWMutex

	tGatherers = NewGatherers()
	mpr        *MultiTRegistry
)

func NewGatherers() *Gatherers {
	return &Gatherers{
		lock:      sync.RWMutex{},
		gatherers: map[string]prometheus.TransactionalGatherer{},
	}
}

type Gatherers struct {
	lock      sync.RWMutex
	gatherers map[string]prometheus.TransactionalGatherer
}

func (c *Gatherers) Add(name string, adapter prometheus.TransactionalGatherer) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.gatherers == nil {
		c.gatherers = map[string]prometheus.TransactionalGatherer{}
	}
	c.gatherers[name] = adapter
}

func (c *Gatherers) GetGatherers() map[string]prometheus.TransactionalGatherer {
	return c.gatherers
}

func (c *Gatherers) Remove(name string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.gatherers != nil {
		if _, ok := c.gatherers[name]; ok {
			delete(c.gatherers, name)
		}
	}
}

func NewCollectors() *Collectors {
	return &Collectors{
		lock:    sync.RWMutex{},
		adapter: map[string]*collectorAdapter{},
	}
}

type Collectors struct {
	lock    sync.RWMutex
	adapter map[string]*collectorAdapter
}

func (c *Collectors) Add(name string, adapter *collectorAdapter) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.adapter == nil {
		c.adapter = map[string]*collectorAdapter{}
	}
	c.adapter[name] = adapter
}

func (c *Collectors) Get(name string) (adapter *collectorAdapter, ok bool) {
	adapter, ok = c.adapter[name]
	return
}

func (c *Collectors) Remove(name string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.adapter != nil {
		if _, ok := c.adapter[name]; ok {
			delete(c.adapter, name)
		}
	}
}

// MultiTRegistry is a TransactionalGatherer that joins gathered metrics from multiple
// transactional gatherers.
//
// It is caller responsibility to ensure two registries have mutually exclusive metric families,
// no deduplication will happen.
type MultiTRegistry struct {
	tGatherers map[string]prometheus.TransactionalGatherer
}

// NewMultiTRegistry creates MultiTRegistry.
func NewMultiTRegistry(tGatherers map[string]prometheus.TransactionalGatherer) *MultiTRegistry {
	return &MultiTRegistry{
		tGatherers: tGatherers,
	}
}

// Gather implements TransactionalGatherer interface.
func (r *MultiTRegistry) Gather() (mfs []*dto.MetricFamily, done func(), err error) {
	errs := prometheus.MultiError{}

	dFns := make([]func(), 0, len(r.tGatherers))
	// TODO(bwplotka): Implement concurrency for those?
	for _, g := range r.tGatherers {
		// TODO(bwplotka): Check for duplicates?
		m, d, err := g.Gather()
		errs.Append(err)

		mfs = append(mfs, m...)
		dFns = append(dFns, d)
	}

	// TODO(bwplotka): Consider sort in place, given metric family in gather is sorted already.
	sort.Slice(mfs, func(i, j int) bool {
		return *mfs[i].Name < *mfs[j].Name
	})
	return mfs, func() {
		for _, d := range dFns {
			d()
		}
	}, errs.MaybeUnwrap()
}

func init() {
	pflag.Usage = func() {
		fmt.Printf(`Usage`)
	}
}

func helper() error {
	if *help {
		pflag.Usage()
		os.Exit(0)
	}
	return nil
}

func main() {
	pflag.Parse()
	if err := helper(); err != nil {
		logrus.Fatal(err)
	}
	if rootlessutil.IsRootless() {
		logrus.Error("net-monitor must be run as root to enter ns")
		os.Exit(1)
	}
	logrus.SetLevel(logrus.InfoLevel)
	if *debug {
		logrus.SetReportCaller(true)
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.ErrorLevel)
	}

	{
		// metric api
		r := gin.Default()
		//pprof.Register(r) // 性能
		//注册组，需要认证
		authStr := fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte("admin:odv@123456")))
		pprofGroup := r.Group("/admin", func(c *gin.Context) {
			auth := c.Request.Header.Get("Authorization")
			if auth != authStr {
				c.Header("www-Authenticate", "Basic")
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			c.Next()
		})
		pprof.RouteRegister(pprofGroup, "pprof")

		r.GET("/metrics", func(c *gin.Context) {
			mfs, _, err := mpr.Gather()
			if err != nil {
				fmt.Println("xxxxx", err)
				return
			}
			for _, mf := range mfs {
				if _, err := expfmt.MetricFamilyToText(c.Writer, mf); err != nil {
					fmt.Println("yyyy", err)
					return
				}
			}
		})

		r.GET("/localaddresses", func(c *gin.Context) {
			c.JSON(200, netflow_collector.GetLocalAddresses())
		})

		r.POST("/localaddresses", func(c *gin.Context) {
			netflow_collector.InsertLocalAddresses(c.Query("ifName"), c.Query("ip"), c.Query("mac"))
			c.JSON(200, netflow_collector.GetLocalAddresses())
		})

		r.DELETE("/localaddresses", func(c *gin.Context) {
			netflow_collector.DeleteLocalAddresses(c.Query("ifName"), c.Query("ip"), c.Query("mac"))
			c.JSON(200, netflow_collector.GetLocalAddresses())
		})

		go func() {
			if err := r.Run(*listen); err != nil {
				log.Fatalln(err)
			}
		}()
	}

	//初始化 mpr
	tGatherers = NewGatherers()
	mpr = NewMultiTRegistry(tGatherers.GetGatherers())

	timer := time.NewTicker(5 * time.Second)
	defer timer.Stop()

	origin, err := netns.Get()
	if err != nil {
		logrus.Fatalf("failed get current netne, %v", err)
	}
	defer origin.Close()
	log.Println("origin netns:", origin)

	netNsMap := map[int]string{}
	reporter := DiffReporter{
		allNode:      map[string]map[string]types.Node{},
		subtract:     []string{},
		allCtxCancel: map[string]context.CancelFunc{},
		add:          []string{},
		originNetns:  origin,
	}

	for {
		select {
		case <-timer.C:
			log.Println("检测 netns 变化")
			tmpNetNsMap, _, _, _, _ := getVethPairInfo(&reporter)

			// 如果检测到 namespace 有变化
			if !cmp.Equal(netNsMap, tmpNetNsMap) {
				diff := cmp.Diff(netNsMap, tmpNetNsMap, cmp.Reporter(&reporter))
				log.Println(diff)
				reporter.Flush()
				netNsMap = tmpNetNsMap
			}
		}
	}
}

func Monitor(ctx context.Context, hostname, ifName string, labels prometheus.Labels) {
	log.Println("监控开始：：", hostname, ifName)
	key := fmt.Sprintf("%s_%s", hostname, ifName)
	if _, ok := netflowCols.Get(key); ok {
		log.Println("key 重复", key)
		return
	}

	var cCtx, cancel = context.WithCancel(ctx)

	netflowCol, err := netflow_collector.NewCollector(cCtx, ifName, hostname, labels)
	if err != nil {
		log.Println("GetCollector error:::", key)
		return
	}

	cd := &collectorAdapter{netflowCol, cancel}
	netflowCols.Add(key, cd)

	pr := prometheus.NewRegistry()
	pr.Register(cd)
	tGatherers.Add(key, prometheus.ToTransactionalGatherer(pr))

	defer netflowCols.Remove(key)
	defer tGatherers.Remove(key)

	if *pushgateway != "" {
		go func() {
			host, _ := os.Hostname()
			pusher := push.New(*pushgateway, "net-monitor").Grouping("instance", host).Grouping("ident", hostname).Grouping("iface", ifName)
			pusher = pusher.Collector(cd)
			go func() {
				ticker := time.NewTicker(1 * time.Minute)
				defer ticker.Stop()
				for {
					// 每分钟清理一次数据
					select {
					case <-ticker.C:
						log.Printf("Cron job: 删除数据 %s", key)
						err := pusher.Delete()
						if err != nil {
							log.Println(err)
						}
					case <-ctx.Done():
						log.Printf("Cron job: 取消删除任务 %s", key)
						return
					}
				}
			}()
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					go func() {
						start := time.Now()
						//f, _ := os.Open(filepath.Join("/proc/", strconv.Itoa(os.Getpid()), "/fd"))
						//ds, _ := f.Readdirnames(-1)
						//f.Close()
						err = pusher.Push()
						if err != nil {
							log.Println(err)
						}
						log.Printf("Cron job: 更新数据 %s : %s", key, time.Since(start).String())
					}()
				case <-ctx.Done():
					log.Printf("Cron job: 取消更新任务 %s", key)
					return
				}
			}
		}()
	}
	select {
	case <-ctx.Done():
		log.Println("退出监控", hostname, ifName)
	}
}

// DiffReporter is a simple custom reporter that only records differences
// detected during comparison.
type DiffReporter struct {
	lock  sync.RWMutex
	path  cmp.Path
	diffs []string

	// 所有 veth，以 namespace 分组
	allNode      map[string]map[string]types.Node
	allCtxCancel map[string]context.CancelFunc

	// 存储变化的 netns
	subtract []string
	add      []string

	originNetns netns.NsHandle
}

func (r *DiffReporter) PushStep(ps cmp.PathStep) {
	r.path = append(r.path, ps)
}

func (r *DiffReporter) Report(rs cmp.Result) {
	if !rs.Equal() {
		vx, vy := r.path.Last().Values()
		// vx 是减少，vy 是增加
		if vx.IsValid() {
			r.subtract = append(r.subtract, vx.String())
		}
		if vy.IsValid() {
			r.add = append(r.add, vy.String())
		}
		r.diffs = append(r.diffs, fmt.Sprintf("%#v:\n\t-: %+v\n\t+: %+v\n", r.path, vx, vy))
	}
}

func (r *DiffReporter) PopStep() {
	r.path = r.path[:len(r.path)-1]
}

func (r *DiffReporter) String() string {
	return strings.Join(r.diffs, "\n")
}

func (r *DiffReporter) AddNetNSNode(nsname string, node types.Node) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if _, ok := r.allNode[nsname]; !ok {
		r.allNode[nsname] = map[string]types.Node{
			node.Veth: node,
		}
	} else {
		r.allNode[nsname][node.Veth] = node
	}
}

func (r *DiffReporter) RemoveNetNSNode(nsname string) {
	r.lock.Lock()
	defer r.lock.Unlock()
	delete(r.allNode, nsname)
	delete(r.allCtxCancel, nsname)
}

// Flush 操作监控增减网卡
func (r *DiffReporter) Flush() {
	for _, ns := range r.add {
		log.Printf("新增 %s %+v", ns, r.allNode[ns])
		ctx, cancel := context.WithCancel(context.Background())
		r.allCtxCancel[ns] = cancel
		for _, v := range r.allNode[ns] {
			tag := v.PeerHostnameInNetns
			if v.PeerHostnameInNetns == "" {
				tag = *ident
			}

			// 新增监控
			log.Println("新增:::", tag, v.Veth)
			// 根据网卡名称（k6t-eth0）判断是否是虚机容器
			labels := prometheus.Labels{}

			{
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()

				links, err := netutil.GetLinksInNs(ns, r.originNetns)
				if err != nil {
					log.Println("err::", err)
				} else {
					for _, link := range links {
						log.Printf("容器网卡：%+v", link.Attrs())
						if strings.HasPrefix(link.Attrs().Name, "k6t-") {
							labels["KubevirtVmPod"] = "true"
						}
					}
				}
			}
			log.Println(labels)
			go Monitor(ctx, tag, v.Veth, labels)
		}
	}

	for _, ns := range r.subtract {
		fmt.Printf("减少 %s %+v", ns, r.allNode[ns])
		if r.allCtxCancel[ns] != nil {
			r.allCtxCancel[ns]()
		} else {
			log.Printf("all ctx:::: %+v", r.allCtxCancel)
		}
		r.RemoveNetNSNode(ns)
	}

	r.add = []string{}
	r.subtract = []string{}
}

func getVethPairInfo(reporter *DiffReporter) (map[int]string, map[string][]types.Node, []types.Node, []types.Node, map[string]*net.IP) {
	// Lock the OS Thread, so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	netNsMap, err := netutil.NetNsMap()
	if err != nil {
		logrus.Fatal(err)
	}
	if len(netNsMap) == 0 {
		logrus.Warn("no netns found")
		os.Exit(0)
	}
	logrus.Debugf("net namespace id <-> name map:\n%+v\n", netNsMap)

	linkList, err := netlink.LinkList()
	if err != nil {
		logrus.Fatal(errors.Unwrap(err))
	}
	logrus.Debugf("net link list:\n%+v\n", linkList)

	bridgeVethM := make(map[string][]types.Node) // map bridge <-> veth paris
	unBridgedVpairs := []types.Node{}
	bridgeIps := make(map[string]*net.IP) // bridge ip
	loS := []types.Node{}                 // loopback

	for _, link := range linkList {
		veth, ok := link.(*netlink.Veth)
		if !ok {
			// skip device not enslaved to any bridge
			logrus.Debugf("skip %s, type: %s", link.Attrs().Name, link.Type())
			continue
		}
		logrus.Debugf("veth device: %+v", veth)

		peerIdx, err := netlink.VethPeerIndex(veth)
		if err != nil {
			logrus.Fatal(err)
		}

		var master netlink.Link
		var vNodes []types.Node
		var bridge = "noneBridge"

		if link.Attrs().MasterIndex == -1 || veth.MasterIndex == 0 {
			logrus.Debugf("%s not has a bridge as master, MasterIndex: %d", veth.Name, link.Attrs().MasterIndex)
			if veth.PeerName == "" {
				p, err := netlink.LinkByIndex(peerIdx)
				if err != nil {
					logrus.Fatal(err)
				}
				veth.PeerName = p.Attrs().Name
			}
			routes, err := netlink.RouteList(link, 4)
			if err != nil {
				logrus.Fatal(err)
			}
			node := types.Node{
				Type:    types.VethType,
				Veth:    veth.Name,
				Peer:    veth.PeerName,
				PeerId:  peerIdx,
				NetNsID: veth.NetNsID,
			}
			if len(routes) > 0 {
				// TODO: more than one IP?
				node.Route = routes[0].Dst.IP
			}
			unBridgedVpairs = append(unBridgedVpairs, node)
			//continue
		} else {
			master, err = netlink.LinkByIndex(veth.Attrs().MasterIndex)
			if err != nil {
				logrus.Fatal(err)
			}

			// if master is not bridge or openvswitch
			if _, ok := master.(*netlink.Bridge); !ok && master.Type() != "openvswitch" {
				// TODO: what if master is not bridge?
				continue
			}
			bridge = master.Attrs().Name
			vNodes, ok = bridgeVethM[bridge]
			if !ok {
				bridgeVethM[bridge] = []types.Node{}
			}
		}

		pair := types.Node{
			Type:             types.VethType,
			Veth:             veth.Name,
			VethIndex:        veth.Index,
			VethHardwareAddr: veth.HardwareAddr,
			PeerId:           peerIdx,
			NetNsID:          veth.NetNsID,
		}
		if peerNetNs, ok := netNsMap[veth.NetNsID]; ok {
			peerInNs, err := netutil.GetPeerInNs(peerNetNs, reporter.originNetns, peerIdx)
			if err != nil {
				logrus.Fatal(err)
			}
			pair.NetNsName = peerNetNs
			pair.PeerNameInNetns = peerInNs.Attrs().Name
			pair.PeerHardwareAddrInNetns = peerInNs.Attrs().HardwareAddr
			pair.Status = peerInNs.Attrs().OperState.String()
			pair.PeerHostnameInNetns, err = netutil.GetHostnameInNs(peerNetNs, reporter.originNetns)
			if err != nil {
				logrus.Errorln(err)
			}

			lo, err := netutil.GetLoInNs(peerNetNs, reporter.originNetns)
			if err == nil && lo != nil {
				loS = append(loS, types.Node{
					Type:      types.LoType,
					NetNsName: peerNetNs,
					Status:    lo.Attrs().OperState.String(),
				})
			}
		} else {
			pair.Orphaned = true
		}

		addrs, err := netlink.AddrList(master, syscall.AF_INET)
		if err != nil {
			logrus.Fatal(err)
		}
		if len(addrs) > 0 {
			pair.Master = &types.Bridge{
				Name: bridge,
				IP:   &addrs[0].IP,
			}
			bridgeIps[bridge] = &addrs[0].IP
		}
		bridgeVethM[bridge] = append(vNodes, pair)
		reporter.AddNetNSNode(pair.NetNsName, pair)
	}
	logrus.Debugf("bridgeVethMap: %+v", bridgeVethM)
	return netNsMap, bridgeVethM, unBridgedVpairs, loS, bridgeIps
}

type collectorAdapter struct {
	collector.Collector
	context.CancelFunc
}

// Describe implements the prometheus.Collector interface.
func (a collectorAdapter) Describe(ch chan<- *prometheus.Desc) {
	// We have to send *some* metric in Describe, but we don't know which ones
	// we're going to get, so just send a dummy metric.
	ch <- prometheus.NewDesc("dummy_metric", "Dummy metric.", nil, nil)
}

// Collect implements the prometheus.Collector interface.
func (a collectorAdapter) Collect(ch chan<- prometheus.Metric) {
	if err := a.Update(ch); err != nil {
		panic(fmt.Sprintf("failed to update collector: %v", err))
	}
}
