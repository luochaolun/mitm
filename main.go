// golang中间人代理

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	//"crypto/rand"
	"crypto/tls"
	//"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/image/webp"
	"image"
	"image/jpeg"
	//"image/gif"
	//"io"
	"golang.org/x/net/netutil"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var (
	mut *sync.Mutex
)

const (
	SAVEDIR = "download/"
	SAVEIMG = true
	SAVETXT = false
)

// MiTMProxy : proxy instance
type MiTMProxy struct {
	mitm      bool
	transport *http.Transport
	signingCertificate
}

func init() {
	mut = new(sync.Mutex)
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	mitm := flag.Bool("mitm", true, "enable mitm sniffing on https")
	addr := flag.String("addr", ":8888", "proxy listen address")
	certfile := flag.String("cert-pem", "certs/mymitm.crt", "ca cert file")
	keyfile := flag.String("key-pem", "certs/mymitm.key", "ca key file")

	flag.Parse()
	proxy := newProxy(*mitm, *certfile, *keyfile)

	log.Printf("Starting Proxy listend: %s : mitm %v\n", *addr, *mitm)
	// log.Fatal(http.ListenAndServe(*addr, proxy))

	// 增加对httpserver做频率限制(最大连接数限制) golang1.9新特性
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal("Listen: %v", err)
	}
	defer l.Close()
	l = netutil.LimitListener(l, 40)

	http.Serve(l, proxy)
}

func (proxy *MiTMProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		if proxy.mitm {
			proxy.mitmRequest(w, r)
		} else {
			proxy.relayHTTPSRequest(w, r)
		}
		return
	}

	proxy.transportHTTPRequest(w, r)
}

func dumpRequest(req *http.Request) bool {
	drawLine()
	defer drawLine()

	fmt.Printf("-> Request : %s %s\n", req.Method, req.URL)
	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return false
	}
	fmt.Println(strings.TrimSpace(string(dump)))
	return true
}

func dumpResponse(resp *http.Response) bool {
	drawLine()
	defer drawLine()

	fmt.Printf("<- Response: %s %s\n", resp.Request.Method, resp.Request.URL)

	ctp := strings.TrimSpace(resp.Header.Get("Content-Type"))

	// 不处理视频
	switch {
	case strings.HasPrefix(ctp, "video/"):
		return false
	}

	// 不处理字体文件、二进制文件
	switch ctp {
	case "application/octet-stream",
		"font/woff":
		return false
	}

	// 头部
	headResp, _ := httputil.DumpResponse(resp, false)
	// 头部 + 正文
	dumpResp, _ := httputil.DumpResponse(resp, true)
	//fmt.Println(strings.TrimSpace(string(dumpResp)))
	//fmt.Println(strings.TrimSpace(string(headResp)))

	// 去除头部，仅留下正文
	html := strings.TrimSpace(strings.Replace(string(dumpResp), string(headResp), "", -1))
	if len(html) == 0 {
		return false
	}

	var body string
	zipStr := strings.TrimSpace(resp.Header.Get("Content-Encoding"))
	if zipStr == "gzip" {
		tmpBody, bBool := unGzipString(html)
		if !bBool {
			return false
		}
		body = tmpBody
	} else {
		body = html
	}

	switch ctp {
	case "image/gif",
		"image/x-icon",
		"image/jpeg",
		"image/png",
		"image/bmp",
		"image/webp":

		if !SAVEIMG {
			return false
		}

		ext := getImgExt(ctp)
		if ext == "" {
			return false
		}

		imgUrl := fmt.Sprintf("%s", resp.Request.URL)
		if ext == ".webp" {
			obj, err := webp.DecodeConfig(bytes.NewReader([]byte(body)))
			if err != nil || obj.Width <= 40 || obj.Height <= 40 {
				return false
			}

			m, err := webp.Decode(bytes.NewReader([]byte(body)))
			if err != nil {
				return false
			}

			savePath := SAVEDIR + "img/" + getHost(imgUrl) + getPathFromImgUrl(imgUrl, ext)
			dir := filepath.Dir(savePath)
			checkDir(dir)
			if isFileOrDirExists(savePath) {
				return false
			}

			outfile, err := os.OpenFile(savePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
			if err != nil {
				return false
			}
			defer outfile.Close()

			if err := jpeg.Encode(outfile, m, &jpeg.Options{80}); err != nil {
				//if err := gif.Encode(outfile, m, &gif.Options{NumColors: 256}); err != nil {
				return false
			}
		} else {
			if !needSaveImg(imgUrl, body) {
				return false
			}

			savePath := SAVEDIR + "img/" + getHost(imgUrl) + getPathFromImgUrl(imgUrl, ext)
			dir := filepath.Dir(savePath)
			checkDir(dir)
			if isFileOrDirExists(savePath) {
				return false
			}

			ioutil.WriteFile(savePath, []byte(body), 0666)
		}
		return true
	}

	switch {
	case strings.HasPrefix(ctp, "text/"):
		if !SAVETXT {
			return false
		}

		txtUrl := fmt.Sprintf("%s", resp.Request.URL)
		savePath := SAVEDIR + "txt/" + getHost(txtUrl) + getPathFromTxtUrl(txtUrl)
		dir := filepath.Dir(savePath)
		checkDir(dir)

		if isFileOrDirExists(savePath) {
			return false
		}
		ioutil.WriteFile(savePath, []byte(body), 0666)
		return true
	}
	return true
}

func newProxy(mitm bool, certfile, keyfile string) *MiTMProxy {
	proxy := &MiTMProxy{
		mitm:      mitm,
		transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, Proxy: http.ProxyFromEnvironment},
	}

	proxy.setupCert(certfile, keyfile)
	return proxy
}

// 解压gzip
func unGzipString(html string) (string, bool) {
	s := strings.NewReader(html)
	sor := ioutil.NopCloser(s)
	defer sor.Close()

	r, err := gzip.NewReader(sor)
	if err != nil {
		return "", false
	}
	defer r.Close()

	respBody, err := ioutil.ReadAll(r)
	if err != nil {
		return "", false
	}
	body := strings.TrimSpace(string(respBody))
	return body, true
}

// 是否需要保存图片
func needSaveImg(imgUrl, body string) bool {
	// 图片宽或高小于40px，不保存
	obj, _, err := image.DecodeConfig(bytes.NewReader([]byte(body)))

	if err != nil {
		if err.Error() == "image: unknown format" {
			return true
		}
		return false
	}

	if obj.Width <= 40 || obj.Height <= 40 {
		return false
	}

	return true
}

func getImgExt(imgFormat string) string {
	switch imgFormat {
	case "image/gif":
		return ".gif"
	case "image/x-icon":
		return ".ico"
	case "image/jpeg":
		return ".jpg"
	case "image/webp":
		return ".webp"
	case "image/png":
		return ".png"
	case "image/bmp":
		return ".bmp"
	default:
		return ""
	}
}

// 生成32位md5字串
func MD5(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// 生成Guid字串
/*
func UniqueId() string {
	b := make([]byte, 48)

	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	return MD5(base64.URLEncoding.EncodeToString(b))
}
*/

func checkDir(dir string) {
	mut.Lock()
	defer mut.Unlock()

	if isFileOrDirExists(dir) {
		return
	}
	os.MkdirAll(dir, 0777)
}

func getHost(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return "default"
	}

	if !strings.Contains(u.Host, ":") {
		return u.Host
	}

	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		return "default"
	}

	return host
}

// 取图片保存路径
func getPathFromImgUrl(s, ext string) string {
	if ext == ".webp" {
		return "/" + MD5(s) + ".jpg"
		//return "/" + MD5(s) + ".gif"
	}

	u, err := url.Parse(s)
	if err != nil {
		return "/" + MD5(s) + ext
	}

	/*if strings.HasSuffix(strings.TrimSpace(u.Path), ext) {
		return strings.TrimSpace(u.Path)
	}

	return strings.TrimSpace(u.Path) + ext*/

	f1 := strings.TrimSpace(filepath.Base(strings.TrimSpace(u.Path)))
	if !strings.Contains(f1, ".") {
		return "/" + MD5(s) + ext
	}

	if strings.HasSuffix(f1, ext) {
		return "/" + f1
	}

	return "/" + f1 + ext
}

// 取txt文件保存路径
func getPathFromTxtUrl(s string) string {
	ext := ".html"
	u, err := url.Parse(s)
	if err != nil {
		return "/" + MD5(s) + ext
	}

	f1 := strings.TrimSpace(filepath.Base(strings.TrimSpace(u.Path)))
	dir := strings.TrimSpace(filepath.Dir(strings.TrimSpace(u.Path)))

	//log.Printf("ff:%s\n", f1)
	if f1 == "" || f1 == "\\" || f1 == "/" {
		f1 = "/index.html"
	}
	if !strings.Contains(f1, ".") {
		f1 = f1 + ext
	}

	arr := []string{}
	for k, v := range u.Query() {
		arr = append(arr, fmt.Sprintf("%s_%s", url.PathEscape(k), url.PathEscape(v[0])))
	}
	arr = append(arr, f1)
	return "/" + dir + "/" + strings.Join(arr, "_")
}

func isFileOrDirExists(f string) bool {
	if _, err := os.Stat(f); os.IsNotExist(err) {
		return false
	}
	return true
}

// 划横线
func drawLine() {
	fmt.Println("---------------------------------------------------------------------")
}
