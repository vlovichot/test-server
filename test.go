package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-ping/ping"
)

// CommonPorts 定义了要扫描的常见端口及其对应的服务名称
var CommonPorts = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	143:  "IMAP",
	443:  "HTTPS",
	465:  "SMTPS",
	993:  "IMAPS",
	995:  "POP3S",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	5900: "VNC",
	8080: "HTTP-Proxy",
}

// scanResult 用于在并发扫描中传递结果
type scanResult struct {
	Port   int
	IsOpen bool
}

// resolveHost 解析输入的目标，返回主机名和 IP 地址
func resolveHost(target string) (string, net.IP) {
	// 如果输入包含协议头，则提取主机名
	parsedURL, err := url.Parse(target)
	hostname := target
	if err == nil && (parsedURL.Scheme == "http" || parsedURL.Scheme == "https'"){
		hostname = parsedURL.Host
	} else if strings.Contains(target, "/") {
		// 处理类似 "google.com/path" 这种没有协议头但有路径的情况
		hostname = strings.Split(target, "/")[0]
	}
	
	// 解析 IP 地址
	ips, err := net.LookupIP(hostname)
	if err != nil {
		fmt.Printf("[!] 错误：无法解析主机名 '%s': %v\n", hostname, err)
		return hostname, nil
	}
	// 返回第一个 IPv4 地址
	for _, ip := range ips {
		if ip.To4() != nil {
			return hostname, ip
		}
	}
	fmt.Printf("[!] 错误：找不到主机 '%s' 的 IPv4 地址\n", hostname)
	return hostname, nil
}

// pingHost 使用 go-ping 库检查主机的可达性
func pingHost(ipAddr net.IP) {
	fmt.Println("\n--- [2] 开始 Ping 测试 ---")
	pinger, err := ping.NewPinger(ipAddr.String())
	if err != nil {
		fmt.Printf("[!] Ping 初始化失败: %v\n", err)
		return
	}
	pinger.Count = 3 // 发送3个 ping 包
	pinger.Timeout = time.Second * 4
	pinger.SetPrivileged(true) // 在 Linux/macOS 上需要 root 权限才能发送 ICMP 包

	err = pinger.Run() // 执行 ping
	if err != nil {
		fmt.Printf("[!] Ping 执行失败: %v\n", err)
		return
	}

	stats := pinger.Statistics() // 获取结果
	if stats.PacketsRecv > 0 {
		fmt.Printf("[+] 主机 %s 可达。\n", ipAddr.String())
		fmt.Printf("    往返时间 (RTT): min/avg/max = %v/%v/%v\n", stats.MinRtt, stats.AvgRtt, stats.MaxRtt)
	} else {
		fmt.Printf("[-] 主机 %s 不可达。\n", ipAddr.String())
	}
}

// scanPorts 并发扫描端口
func scanPorts(ipAddr net.IP, portsToScan map[int]string) []int {
	fmt.Println("\n--- [3] 开始端口扫描 ---")
	var openPorts []int
	var wg sync.WaitGroup
	results := make(chan scanResult, len(portsToScan))

	for port, service := range portsToScan {
		wg.Add(1)
		go func(p int, s string) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", ipAddr, p)
			conn, err := net.DialTimeout("tcp", address, 1*time.Second)
			if err != nil {
				results <- scanResult{Port: p, IsOpen: false}
				return
			}
			conn.Close()
			results <- scanResult{Port: p, IsOpen: true}
			fmt.Printf("[+] 端口 %d (%s) 是开放的。\n", p, s)
		}(port, service)
	}

	// 等待所有 goroutine 完成
	wg.Wait()
	close(results)

	for result := range results {
		if result.IsOpen {
			openPorts = append(openPorts, result.Port)
		}
	}

	if len(openPorts) == 0 {
		fmt.Println("[-] 未发现开放的常见端口。")
	}

	// 对结果进行排序以便于查看
	sort.Ints(openPorts)
	return openPorts
}

// getBanner 尝试获取服务 Banner
func getBanner(ipAddr net.IP, port int) {
	address := fmt.Sprintf("%s:%d", ipAddr, port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	banner := strings.TrimSpace(string(buffer[:n]))
	if banner != "" {
		fmt.Printf("  - 端口 %d Banner: %s\n", port, banner)
	}
}

// getSSLCertInfo 获取并显示 SSL 证书信息
func getSSLCertInfo(hostname string, port int) {
	fmt.Printf("\n--- [4] 获取端口 %d 的 SSL 证书信息 ---\n", port)
	conf := &tls.Config{
		InsecureSkipVerify: true, // 不验证证书链，只为获取信息
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", hostname, port), conf)
	if err != nil {
		fmt.Printf("[!] 无法建立 TLS 连接: %v\n", err)
		return
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		fmt.Println("[-] 服务器未提供证书。")
		return
	}

	cert := certs[0]
	fmt.Printf("[+] 通用名称 (Common Name): %s\n", cert.Subject.CommonName)
	fmt.Printf("[+] 备用名称 (SAN): %v\n", cert.DNSNames)
	fmt.Printf("[+] 颁发者: %s\n", cert.Issuer.CommonName)
	fmt.Printf("[+] 证书有效期从: %s\n", cert.NotBefore.Format("2006-01-02"))
	fmt.Printf("[+] 证书有效期至: %s\n", cert.NotAfter.Format("2006-01-02"))

	daysLeft := int(cert.NotAfter.Sub(time.Now()).Hours() / 24)
	if daysLeft < 0 {
		fmt.Println("[!] 警告：证书已过期！")
	} else if daysLeft < 30 {
		fmt.Printf("[!] 警告：证书将在 %d 天内过期！\n", daysLeft)
	} else {
		fmt.Printf("[+] 证书剩余有效期: %d 天。\n", daysLeft)
	}
}

// getHTTPHeaders 获取 HTTP 头部信息
func getHTTPHeaders(hostname string, port int) {
	fmt.Printf("\n--- [5] 获取端口 %d 的 HTTP 标头 ---\n", port)
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	targetURL := fmt.Sprintf("%s://%s:%d", scheme, hostname, port)

	// 创建一个自定义的 http.Client 以跳过 TLS 验证（如果需要）
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("HEAD", targetURL, nil)
	if err != nil {
		fmt.Printf("[!] 创建请求失败: %v\n", err)
		return
	}
	req.Header.Set("User-Agent", "Go-Server-Info-Detector/1.0")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[!] 获取 HTTP 标头时出错: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("[+] 服务器响应状态: %s\n", resp.Status)
	fmt.Println("[+] 响应标头:")
	fmt.Println("--------------------")
	for key, values := range resp.Header {
		fmt.Printf("%s: %s\n", key, strings.Join(values, ", "))
	}
	fmt.Println("--------------------")
}

func main() {
	fmt.Print("请输入目标域名或 IP 地址 (例如: example.com 或 8.8.8.8): ")
	reader := bufio.NewReader(os.Stdin)
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)

	if target == "" {
		fmt.Println("输入不能为空。")
		return
	}

	hostname, ipAddr := resolveHost(target)
	if ipAddr == nil {
		return
	}

	fmt.Println("\n--- [1] 目标基本信息 ---")
	fmt.Printf("[+] 主机名: %s\n", hostname)
	fmt.Printf("[+] IP 地址: %s\n", ipAddr.String())

	// 执行 Ping 测试
	pingHost(ipAddr)

	// 执行端口扫描
	openPorts := scanPorts(ipAddr, CommonPorts)

	// 对开放的端口进行详细探测
	if len(openPorts) > 0 {
		fmt.Println("\n--- [+] 开放端口上的服务探测 ---")
		for _, port := range openPorts {
			getBanner(ipAddr, port)
		}
		for _, port := range openPorts {
			if port == 443 {
				getSSLCertInfo(hostname, port)
			}
			if port == 80 || port == 443 || port == 8080 {
				getHTTPHeaders(hostname, port)
			}
		}
	}

	fmt.Println("\n检测完成。")
}
