package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type TicketResDTO struct {
	Data    Data  `json:"data"`
	Success int64 `json:"success"`
}

type Data struct {
	Username            string `json:"username"`
	Ticket              string `json:"ticket"`
	CSRFPreventionToken string `json:"CSRFPreventionToken"`
	Cap                 Cap    `json:"cap"`
}

type Cap struct {
	Vms     map[string]int64 `json:"vms"`
	Dc      Dc               `json:"dc"`
	SDN     SDN              `json:"sdn"`
	Access  Access           `json:"access"`
	Nodes   map[string]int64 `json:"nodes"`
	Storage Storage          `json:"storage"`
}

type Access struct {
	PermissionsModify int64 `json:"Permissions.Modify"`
	UserModify        int64 `json:"User.Modify"`
	GroupAllocate     int64 `json:"Group.Allocate"`
}

type Dc struct {
	SysAudit    int64 `json:"Sys.Audit"`
	SDNAudit    int64 `json:"SDN.Audit"`
	SDNAllocate int64 `json:"SDN.Allocate"`
}

type SDN struct {
	PermissionsModify int64 `json:"Permissions.Modify"`
	SDNAllocate       int64 `json:"SDN.Allocate"`
	SDNAudit          int64 `json:"SDN.Audit"`
}

type Storage struct {
	DatastoreAllocate         int64 `json:"Datastore.Allocate"`
	DatastoreAudit            int64 `json:"Datastore.Audit"`
	DatastoreAllocateTemplate int64 `json:"Datastore.AllocateTemplate"`
	DatastoreAllocateSpace    int64 `json:"Datastore.AllocateSpace"`
	PermissionsModify         int64 `json:"Permissions.Modify"`
}

type GetLVMResDTO struct {
	Data DataLvm `json:"data"`
}

type DataLvm struct {
	Children []DataChild `json:"children"`
	Leaf     int64       `json:"leaf"`
}

type DataChild struct {
	Size     int64        `json:"size"`
	Leaf     int64        `json:"leaf"`
	Free     int64        `json:"free"`
	Name     string       `json:"name"`
	Lvcount  int64        `json:"lvcount"`
	Children []ChildChild `json:"children"`
}

type ChildChild struct {
	Leaf int64  `json:"leaf"`
	Size int64  `json:"size"`
	Free int64  `json:"free"`
	Name string `json:"name"`
}

type GetLvmthin struct {
	Data []Datum `json:"data"`
}

type Datum struct {
	Ctime        string `json:"ctime"`
	Used         int64  `json:"used"`
	LVSize       int64  `json:"lv_size"`
	MetadataUsed int64  `json:"metadata_used"`
	MetadataSize int64  `json:"metadata_size"`
	LVType       string `json:"lv_type"`
	LV           string `json:"lv"`
}

//判断元素是否在切片中
func InSlice(items []float64, item float64) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

//生成数据数组：[{"ip":"xxxx","usage":"xx","free":"xx"},...]
func getHostLVMArry() []map[string]string {
	hostLVMArry := make([]map[string]string, 0, 10)
	for ip, hostname := range ipHostnameMap {
		// fmt.Println(ip)
		token, cookie, err := getToken("user", "password", ip)
		// go getToken()
		if err != nil {
			panic(err)
		}
		// log.Println(token)
		//返回lvm数据
		lvm, err := getLvm(token, cookie, ip, hostname)
		if err != nil {
			panic(err)
		}
		if v, ok := lvm.(GetLvmthin); ok {
			if len(v.Data) == 0 {
				continue
			}
			size := v.Data[0].LVSize
			used := v.Data[0].Used
			free_TB := fmt.Sprintf("%.2f", float32(size-used)/(1024*1024*1024*1024))
			usage := fmt.Sprintf("%.2f", float32(used)/float32(size)*100)
			hostLvmMap := make(map[string]string)
			hostLvmMap["ip"] = ip
			hostLvmMap["usage"] = usage
			hostLvmMap["free"] = free_TB
			hostLVMArry = append(hostLVMArry, hostLvmMap)
			// fmt.Printf("host_ip:%v, lvm_free:%vTiB---%T, used:%v ---%T\n", ip, free_TB, free_TB, usage, usage)
		}

	}
	// fmt.Println(hostLVMArry)
	return hostLVMArry
}

//排序
func sortUsages(hostLVMArry []map[string]string) []float64 {
	var usages []float64
	for _, v := range hostLVMArry {
		usage_float, _ := strconv.ParseFloat(v["usage"], 64)
		if ok := InSlice(usages, usage_float); !ok {
			usages = append(usages, usage_float)
		}
	}
	sort.Float64s(usages)
	// fmt.Println(usages)
	return usages
}

func printExecTime() {
	exeTime := time.Now()
	fmt.Printf("exec time：%d-%02d-%02d %02d:%02d:%02d %v\n\n",
		exeTime.Year(),
		exeTime.Month(),
		exeTime.Day(),
		exeTime.Hour(),
		exeTime.Minute(),
		exeTime.Second(),
		exeTime.Weekday().String())
	fmt.Printf("host_ip\t\t|\tused%%\t|\tfree_size(TiB)\n")
}

func printLvmInfo(usageArr []float64, hostLVMArry []map[string]string) {
	for i := len(usageArr) - 1; i >= 0; i-- {
		for _, v := range hostLVMArry {
			usage_float, _ := strconv.ParseFloat(v["usage"], 64)
			if usage_float == usageArr[i] {
				// fmt.Printf("成功找到 %v", v["used"])
				usage := v["usage"]
				free := v["free"]
				ip := v["ip"]
				fmt.Printf("%v\t|\t%v\t|\t%v\n", ip, usage, free)
			}
		}
	}
}

// POST /api2/json/access/ticket
func getToken(username, password, ip string) (token string, cookie string, err error) {

	url := "https://" + ip + ":8006/api2/json/access/ticket"
	method := "POST"

	payload := strings.NewReader("username=" + username + "&password=" + password + "&realm=pam")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
			DisableCompression: true,
		},
	}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return
	}

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	// fmt.Println(string(body))
	// json unmarshal
	var ticketResDTO TicketResDTO
	json.Unmarshal(body, &ticketResDTO)
	return ticketResDTO.Data.CSRFPreventionToken, ticketResDTO.Data.Ticket, nil
}

// GET /api2/json/nodes/{node}/disks/lvmthin
func getLvm(token, cookie, ip, hostname string) (interface{}, error) {
	url := "https://" + ip + ":8006/api2/json/nodes/" + hostname + "/disks/lvmthin"
	method := "GET"

	// cookie := &http.Cookie{
	// 	Name:  "PVEAuthCookie",
	// 	Value: token[13:],
	// 	// MaxAge: 300,
	// }

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
			DisableCompression: true,
		},
	}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	req.Header.Add("Cookie", "PVEAuthCookie="+cookie)
	req.Header.Add("CSRFPreventionToken", token)
	// req.AddCookie(cookie)
	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	// fmt.Println(string(body))
	// json unmarshal
	var getLvmthin GetLvmthin
	json.Unmarshal(body, &getLvmthin)
	return getLvmthin, nil
}

// ip_hostname map
var ipHostnameMap = map[string]string{
	//填入服务器IP和主机名,数量不限
	"ip1":   "ip1_hostname",
	"ip2":   "ip2_hostname",
	"ip3":   "ip3_hostname",


}

func main() {

	hostLVMArry := getHostLVMArry()
	usages := sortUsages(hostLVMArry)
	printExecTime()
	printLvmInfo(usages, hostLVMArry)

}
