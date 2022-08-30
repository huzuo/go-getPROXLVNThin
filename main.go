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
		usages = append(usages, usage_float)
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
	"172.25.9.87":   "prox9-87",
	"172.25.9.86":   "prox9-86",
	"172.25.9.19":   "PROX-19",
	"172.25.9.15":   "PROX-15",
	"172.25.9.3":    "prox-3",
	"172.28.1.11":   "prox1-11",
	"172.25.18.242": "prox-242",
	"172.25.18.210": "PROX-18-210",
	"172.25.18.63":  "prox18-63",
	"172.25.18.39":  "prox-1839",
	"172.25.18.30":  "prox-1830",
	"172.25.18.23":  "prox-1823",
	"172.25.18.14":  "prox-1814",
	"172.25.18.11":  "prox-1811",
	"172.25.16.5":   "pve-16-5",
	"172.25.13.5":   "prox-13-5",
	"172.25.9.110":  "prox-110",
	"172.25.9.91":   "prox-91",
	"172.25.9.78":   "prox-78",
	"172.25.9.77":   "prox-77",
	"172.25.9.76":   "prox-76",
	"172.25.9.75":   "prox-75",
	"172.25.9.74":   "prox-74",
	"172.25.9.73":   "prox-73",
	"172.25.9.72":   "prox-72",
	"172.25.9.71":   "prox-71",
	"172.25.9.70":   "prox-70",
	"172.25.9.69":   "prox-69",
	"172.25.9.68":   "prox-68",
	"172.25.9.57":   "prox-57",
	"172.25.9.49":   "prox-49",
	"172.25.9.48":   "prox-48",
	"172.25.9.41":   "prox-41",
	"172.25.9.38":   "prox-38",
	"172.25.9.31":   "prox-31",
	"172.25.9.26":   "prox-26",
	"172.25.9.21":   "prox-21",
	"172.25.9.18":   "prox-18",
	"172.25.9.17":   "prox-17",
	"172.25.9.14":   "prox-14",
	"172.25.9.13":   "prox-13",
	"172.25.9.11":   "prox-11",
	"172.25.9.9":    "prox-9",
	"172.28.1.35":   "prox1-35",
	"172.28.1.36":   "prox1-36",
	"172.28.1.25":   "prox1-25",
	"172.28.1.26":   "prox1-26",
	"172.28.1.15":   "prox1-15",
	"172.28.1.16":   "prox1-16",
	"172.28.1.21":   "prox1-21",
}

func main() {

	hostLVMArry := getHostLVMArry()
	usages := sortUsages(hostLVMArry)
	printExecTime()
	printLvmInfo(usages, hostLVMArry)

}
