package netutil

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
)

const (
	// https://man7.org/linux/man-pages/man8/ip-netns.8.html
	netNsPath = "/var/run/netns"
	// default docker dir
	//docNetNSkerPath = "/var/run/docker/netns"

	// 从 mobyRuntimePath 目录遍历 state.json 文件获取 netns 路径
	mobyRuntimePath = "/var/run/docker/runtime-runc/moby/"
)

//dEs, err := os.ReadDir(docNetNSkerPath)

// https://github.com/shemminger/iproute2/blob/main/ip/ipnetns.c#L432
// https://github.com/shemminger/iproute2/blob/main/ip/ipnetns.c#L106
func NetNsMap() (map[int]string, error) {
	nsArr, err := listNetNsPath()
	if err != nil {
		return nil, errors.Wrap(err, "list netns")
	}
	logrus.Debugf("netns paths: %+v", nsArr)
	m := make(map[int]string)
	for _, path := range nsArr {
		id, err := NsidFromPath(path)
		if err != nil {
			return nil, errors.Wrapf(err, "get nsid from path `%s`", path)
		}
		// -1 if the namespace does not have an ID set.
		if id == -1 {
			continue
		}
		m[id] = path
	}
	return m, nil
}

func NsidFromPath(path string) (int, error) {
	netnsFd, err := netns.GetFromPath(path)
	if err != nil {
		return 0, errors.Wrapf(err, "fail get netns from path %s", path)
	}
	defer netnsFd.Close()
	id, err := netlink.GetNetNsIdByFd(int(netnsFd))
	if err != nil {
		return 0, err
	}

	return id, nil
}

func listNetNsPath() ([]string, error) {
	var ns []string

	es, err := os.ReadDir(netNsPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	} else {
		for _, e := range es {
			ns = append(ns, filepath.Join(netNsPath, e.Name()))
		}
	}
	//dEs, err := os.ReadDir(docNetNSkerPath)
	//if err != nil && !os.IsNotExist(err) {
	//	return nil, err
	//} else {
	//	for _, e := range dEs {
	//		ns = append(ns, filepath.Join(docNetNSkerPath, e.Name()))
	//	}
	//}
	//

	dEs, err := os.ReadDir(mobyRuntimePath)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	} else {
		for _, e := range dEs {
			stateFile := filepath.Join(mobyRuntimePath, e.Name(), "state.json")
			if bs, err := os.ReadFile(stateFile); err == nil {
				nsPath := gjson.GetBytes(bs, "namespace_paths.NEWNET").String()
				if ok, err := PathExists(nsPath); err == nil && ok {
					ns = append(ns, nsPath)
				}
			}
		}
	}
	logrus.Println(ns)
	return ns, nil
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// GetPeerInNs enter target netns to get veth peer's name
// root needed
func GetPeerInNs(ns string, origin netns.NsHandle, peerIdx int) (netlink.Link, error) {
	return netnsGetName(ns, origin, func() (netlink.Link, error) {
		return netlink.LinkByIndex(peerIdx)
	})
}

func GetLoInNs(ns string, origin netns.NsHandle) (netlink.Link, error) {
	return netnsGetName(ns, origin, func() (netlink.Link, error) {
		return netlink.LinkByName("lo")
	})
}

func GetLinksInNs(ns string, origin netns.NsHandle) ([]netlink.Link, error) {
	return netnsGetLinks(ns, origin, func() ([]netlink.Link, error) {
		return netlink.LinkList()
	})
}

func netnsGetLinks(ns string, origin netns.NsHandle, fn func() ([]netlink.Link, error)) (links []netlink.Link, err error) {
	// Switch back to the original namespace
	defer netns.Set(origin)

	hd, err := netns.GetFromPath(ns)
	if err != nil {
		return nil, err
	}
	defer hd.Close()
	if err := netns.Set(hd); err != nil {
		return nil, err
	}
	return fn()
}

func netnsGetName(ns string, origin netns.NsHandle, fn func() (netlink.Link, error)) (link netlink.Link, err error) {
	// Switch back to the original namespace
	defer netns.Set(origin) //nolint: errcheck

	hd, err := netns.GetFromPath(ns)
	if err != nil {
		return nil, err
	}
	defer hd.Close()
	if err := netns.Set(hd); err != nil {
		return nil, err
	}
	return fn()
}

func GetHostnameInNs(ns string, origin netns.NsHandle) (string, error) {
	return netnsGetNameStr(ns, origin, func() (string, error) {
		return os.Hostname()
	})
}

func netnsGetNameStr(ns string, origin netns.NsHandle, fn func() (string, error)) (str string, err error) {
	// Switch back to the original namespace
	defer netns.Set(origin) //nolint: errcheck

	var hd netns.NsHandle
	if strings.HasPrefix(ns, "/proc") {
		//	/proc/19338/ns/net
		hd, err = netns.GetFromPath(filepath.Join("/proc", strings.Split(ns, "/")[2], "/ns/uts"))
	} else {
		hd, err = netns.GetFromPath(filepath.Join("/run/utsns/", filepath.Base(ns)))
	}
	if err != nil {
		return "", err
	}
	defer hd.Close()

	if err := unix.Setns(int(hd), unix.CLONE_NEWUTS); err != nil {
		return "", errors.New(fmt.Sprintln("++++++++++++++", err))
	}
	return fn()
}
