package ibclient

import (
	"net/http"
)

type FakeRequestBuilder struct {
	hostConfig HostConfig

	r   RequestType
	obj IBObject
	ref string

	urlStr  string
	bodyStr []byte
	req     *http.Request
}

func (rb *FakeRequestBuilder) Init(cfg HostConfig) {
	rb.hostConfig = cfg
}

func (rb *FakeRequestBuilder) BuildURL(r RequestType, objType string, ref string, returnFields []string, queryParams QueryParams) string {
	return rb.urlStr
}

func (rb *FakeRequestBuilder) BuildBody(r RequestType, obj IBObject) []byte {
	return []byte{}
}

func (rb *FakeRequestBuilder) BuildRequest(r RequestType, obj IBObject, ref string, queryParams QueryParams) (*http.Request, error) {
	// Expect(r).To(Equal(rb.r))
	// if rb.obj == nil {
	// 	Expect(obj).To(BeNil())
	// } else {
	// 	Expect(obj).To(Equal(rb.obj))
	// }
	// Expect(ref).To(Equal(rb.ref))

	return rb.req, nil
}

type FakeHTTPRequestor struct {
	config TransportConfig

	req *http.Request
	res []byte
}

func (hr *FakeHTTPRequestor) Init(config TransportConfig) {
	hr.config = config
}

func (hr *FakeHTTPRequestor) SendRequest(req *http.Request) ([]byte, error) {
	// Expect(req).To(Equal(hr.req))

	return hr.res, nil
}

func MockValidateConnector(c *Connector) (err error) {
	return
}

// var _ = Describe("Connector", func() {

// 	Describe("WapiRequestBuilder", func() {
// 		host := "172.22.18.66"
// 		version := "2.2"
// 		port := "443"
// 		username := "myname"
// 		password := "mysecrete!"
// 		hostCfg := HostConfig{
// 			Host:     host,
// 			Version:  version,
// 			Port:     port,
// 			Username: username,
// 			Password: password,
// 		}

// 		wrb := WapiRequestBuilder{HostConfig: hostCfg}

// 		Describe("BuildUrl", func() {
// 			Context("for CREATE request", func() {
// 				objType := "networkview"
// 				ref := ""
// 				returnFields := []string{}
// 				var queryParams QueryParams
// 				It("should return expected url string for CREATE request when forceProxy is false", func() {
// 					queryParams.forceProxy = false //disable proxy
// 					expectedURLStr := fmt.Sprintf("https://%s:%s/wapi/v%s/%s",
// 						host, port, version, objType)
// 					urlStr := wrb.BuildUrl(CREATE, objType, ref, returnFields, queryParams)
// 					Expect(urlStr).To(Equal(expectedURLStr))
// 				})
// 				It("should return expected url string for CREATE request when forceProxy is true", func() {
// 					queryParams.forceProxy = true //proxy enabled
// 					expectedURLStr := fmt.Sprintf("https://%s:%s/wapi/v%s/%s",
// 						host, port, version, objType)
// 					urlStr := wrb.BuildUrl(CREATE, objType, ref, returnFields, queryParams)
// 					Expect(urlStr).To(Equal(expectedURLStr))

// 				})
// 			})
// 			Context("for GET request", func() {
// 				objType := "network"
// 				ref := ""
// 				returnFields := []string{"extattrs", "network", "network_view"}
// 				returnFieldsStr := "_return_fields" + "=" + url.QueryEscape(strings.Join(returnFields, ","))
// 				var queryParams QueryParams
// 				It("should return expected url string for GET for the return fields when forceProxy is false", func() {
// 					queryParams.forceProxy = false // disable proxy
// 					expectedURLStr := fmt.Sprintf("https://%s:%s/wapi/v%s/%s?%s",
// 						host, port, version, objType, returnFieldsStr)
// 					urlStr := wrb.BuildUrl(GET, objType, ref, returnFields, queryParams)
// 					Expect(urlStr).To(Equal(expectedURLStr))
// 				})
// 				It("should return expected url string for GET for the return fields when forceProxy is true", func() {
// 					queryParams.forceProxy = true // proxy enabled
// 					qry := "_proxy_search=GM"
// 					expectedURLStr := fmt.Sprintf("https://%s:%s/wapi/v%s/%s?%s&%s",
// 						host, port, version, objType, qry, returnFieldsStr)
// 					urlStr := wrb.BuildUrl(GET, objType, ref, returnFields, queryParams)
// 					Expect(urlStr).To(Equal(expectedURLStr))
// 				})
// 			})
// 			Context("for DELETE request", func() {
// 				objType := ""
// 				ref := "fixedaddress/ZG5zLmJpbmRfY25h:12.0.10.1/external"
// 				returnFields := []string{}
// 				var queryParams QueryParams
// 				It("should return expected url string for DELETE request when forceProxy is false", func() {
// 					queryParams.forceProxy = false //disable proxy
// 					expectedURLStr := fmt.Sprintf("https://%s:%s/wapi/v%s/%s",
// 						host, port, version, ref)
// 					urlStr := wrb.BuildUrl(DELETE, objType, ref, returnFields, queryParams)
// 					Expect(urlStr).To(Equal(expectedURLStr))
// 				})
// 				It("should return expected url string for DELETE request when forceProxy is true", func() {
// 					queryParams.forceProxy = true //proxy enabled
// 					expectedURLStr := fmt.Sprintf("https://%s:%s/wapi/v%s/%s",
// 						host, port, version, ref)
// 					urlStr := wrb.BuildUrl(DELETE, objType, ref, returnFields, queryParams)
// 					Expect(urlStr).To(Equal(expectedURLStr))
// 				})
// 			})

// 		})

// 		Describe("BuildBody", func() {
// 			It("should return expected body string for CREATE request", func() {
// 				networkView := "private-view"
// 				cidr := "172.22.18.0/24"
// 				eaKey := "Network Name"
// 				eaVal := "yellow-net"
// 				ea := EA{eaKey: eaVal}
// 				nw := NewNetwork(Network{NetviewName: networkView, Cidr: cidr, Ea: ea})

// 				netviewStr := `"network_view":"` + networkView + `"`
// 				networkStr := `"network":"` + cidr + `"`
// 				eaStr := `"extattrs":{"` + eaKey + `":{"value":"` + eaVal + `"}}`
// 				expectedBodyStr := "{" + strings.Join([]string{netviewStr, networkStr, eaStr}, ",") + "}"

// 				bodyStr := wrb.BuildBody(CREATE, nw)
// 				Expect(string(bodyStr)).To(Equal(expectedBodyStr))
// 			})
// 		})

// 		Describe("BuildBody", func() {
// 			It("should return expected body for GET by EA request", func() {
// 				networkView := "private-view"
// 				cidr := "172.22.18.0/24"
// 				eaKey := "Network Name"
// 				eaVal := "yellow-net"
// 				eaSearch := EASearch{eaKey: eaVal}
// 				nw := NewNetwork(Network{NetviewName: networkView, Cidr: cidr})
// 				nw.eaSearch = eaSearch

// 				netviewStr := `"network_view":"` + networkView + `"`
// 				networkStr := `"network":"` + cidr + `"`
// 				eaSearchStr := `"*` + eaKey + `":"` + eaVal + `"`
// 				expectedBodyStr := "{" + strings.Join([]string{netviewStr, networkStr, eaSearchStr}, ",") + "}"
// 				bodyStr := wrb.BuildBody(GET, nw)

// 				Expect(string(bodyStr)).To(Equal(expectedBodyStr))
// 			})
// 		})

// 		Describe("BuildRequest", func() {
// 			Context("for CREATE request", func() {
// 				networkView := "private-view"
// 				cidr := "172.22.18.0/24"
// 				eaKey := "Network Name"
// 				eaVal := "yellow-net"
// 				ea := EA{eaKey: eaVal}
// 				nw := NewNetwork(Network{NetviewName: networkView, Cidr: cidr, Ea: ea})
// 				netviewStr := `"network_view":"` + networkView + `"`
// 				networkStr := `"network":"` + cidr + `"`
// 				eaStr := `"extattrs":{"` + eaKey + `":{"value":"` + eaVal + `"}}`
// 				expectedBodyStr := "{" + strings.Join([]string{netviewStr, networkStr, eaStr}, ",") + "}"
// 				var queryParams QueryParams
// 				It("should return expected Http Request for CREATE request when forceProxy is false", func() {
// 					queryParams.forceProxy = false //disable proxy
// 					hostStr := fmt.Sprintf("%s:%s", host, port)
// 					req, err := wrb.BuildRequest(CREATE, nw, "", queryParams)
// 					Expect(err).To(BeNil())
// 					Expect(req.Method).To(Equal("POST"))
// 					Expect(req.URL.Host).To(Equal(hostStr))
// 					Expect(req.URL.Path).To(Equal(fmt.Sprintf("/wapi/v%s/%s", version, nw.ObjectType())))
// 					Expect(req.Header["Content-Type"]).To(Equal([]string{"application/json"}))
// 					Expect(req.Host).To(Equal(hostStr))
// 					actualUsername, actualPassword, ok := req.BasicAuth()
// 					Expect(ok).To(BeTrue())
// 					Expect(actualUsername).To(Equal(username))
// 					Expect(actualPassword).To(Equal(password))
// 					bodyLen := 1000
// 					actualBody := make([]byte, bodyLen)
// 					n, rderr := req.Body.Read(actualBody)
// 					_ = req.Body.Close()
// 					Expect(rderr).To(BeNil())
// 					Expect(n < bodyLen).To(BeTrue())
// 					actualBodyStr := string(actualBody[:n])
// 					Expect(actualBodyStr).To(Equal(expectedBodyStr))
// 				})
// 				It("should return expected Http Request for CREATE request when forceProxy is true", func() {
// 					queryParams.forceProxy = true //proxy enabled
// 					hostStr := fmt.Sprintf("%s:%s", host, port)
// 					req, err := wrb.BuildRequest(CREATE, nw, "", queryParams)
// 					Expect(err).To(BeNil())
// 					Expect(req.Method).To(Equal("POST"))
// 					Expect(req.URL.Host).To(Equal(hostStr))
// 					Expect(req.URL.Path).To(Equal(fmt.Sprintf("/wapi/v%s/%s", version, nw.ObjectType())))
// 					Expect(req.Header["Content-Type"]).To(Equal([]string{"application/json"}))
// 					Expect(req.Host).To(Equal(hostStr))
// 					actualUsername, actualPassword, ok := req.BasicAuth()
// 					Expect(ok).To(BeTrue())
// 					Expect(actualUsername).To(Equal(username))
// 					Expect(actualPassword).To(Equal(password))
// 					bodyLen := 1000
// 					actualBody := make([]byte, bodyLen)
// 					n, rderr := req.Body.Read(actualBody)
// 					_ = req.Body.Close()
// 					Expect(rderr).To(BeNil())
// 					Expect(n < bodyLen).To(BeTrue())
// 					actualBodyStr := string(actualBody[:n])
// 					Expect(actualBodyStr).To(Equal(expectedBodyStr))
// 				})
// 			})

// 		})
// 	})

// 	Describe("Connector Object Methods", func() {

// 		host := "172.22.18.66"
// 		version := "2.2"
// 		port := "443"
// 		username := "myname"
// 		password := "mysecrete!"
// 		httpRequestTimeout := 120
// 		httpPoolConnections := 100

// 		hostConfig := HostConfig{
// 			Host:     host,
// 			Version:  version,
// 			Port:     port,
// 			Username: username,
// 			Password: password,
// 		}
// 		transportConfig := NewTransportConfig("false", httpRequestTimeout, httpPoolConnections)

// 		Describe("CreateObject", func() {
// 			netviewName := "private-view"
// 			eaKey := "CMP Type"
// 			eaVal := "OpenStack"
// 			netViewObj := NewNetworkView(NetworkView{
// 				Name: netviewName,
// 				Ea:   EA{eaKey: eaVal},
// 			})

// 			requestType := RequestType(CREATE)
// 			eaStr := `"extattrs":{"` + eaKey + `":{"value":"` + eaVal + `"}}`
// 			netviewStr := `"network_view":"` + netviewName + `"`
// 			urlStr := fmt.Sprintf("https://%s:%s/wapi/v%s/%s",
// 				host, port, version, netViewObj.ObjectType())
// 			bodyStr := []byte("{" + strings.Join([]string{netviewStr, eaStr}, ",") + "}")
// 			httpReq, _ := http.NewRequest(requestType.toMethod(), urlStr, bytes.NewBuffer(bodyStr))
// 			frb := &FakeRequestBuilder{
// 				r:   requestType,
// 				obj: netViewObj,
// 				ref: "",

// 				urlStr:  urlStr,
// 				bodyStr: bodyStr,
// 				req:     httpReq,
// 			}

// 			expectRef := "networkview/ZG5zLm5ldHdvcmtfdmlldyQyMw:global_view/false"
// 			fakeref := `"` + expectRef + `"`
// 			fhr := &FakeHttpRequestor{
// 				config: transportConfig,

// 				req: httpReq,
// 				res: []byte(fakeref),
// 			}

// 			OrigValidateConnector := ValidateConnector
// 			ValidateConnector = MockValidateConnector
// 			defer func() { ValidateConnector = OrigValidateConnector }()
// 			conn, err := NewConnector(hostConfig, transportConfig,
// 				frb, fhr)

// 			if err != nil {
// 				Fail("Error creating Connector")
// 			}
// 			It("should return expected object", func() {
// 				actualRef, err := conn.CreateObject(netViewObj)

// 				Expect(err).To(BeNil())
// 				Expect(actualRef).To(Equal(expectRef))
// 			})
// 		})

// 		Describe("DeleteObject", func() {
// 			ref := "fixedaddress/ZG5zLmJpbmRfY25h:12.0.10.1/external"

// 			requestType := RequestType(DELETE)
// 			urlStr := fmt.Sprintf("https://%s:%s/wapi/v%s/%s",
// 				host, port, version, ref)
// 			bodyStr := []byte{}
// 			httpReq, _ := http.NewRequest(requestType.toMethod(), urlStr, bytes.NewBuffer(bodyStr))
// 			frb := &FakeRequestBuilder{
// 				r:   requestType,
// 				obj: nil,
// 				ref: ref,

// 				urlStr:  urlStr,
// 				bodyStr: bodyStr,
// 				req:     httpReq,
// 			}

// 			expectRef := ref
// 			fakeref := `"` + expectRef + `"`
// 			fhr := &FakeHttpRequestor{
// 				config: transportConfig,

// 				req: httpReq,
// 				res: []byte(fakeref),
// 			}

// 			OrigValidateConnector := ValidateConnector
// 			ValidateConnector = MockValidateConnector
// 			defer func() { ValidateConnector = OrigValidateConnector }()
// 			conn, err := NewConnector(hostConfig, transportConfig,
// 				frb, fhr)

// 			if err != nil {
// 				Fail("Error creating Connector")
// 			}
// 			It("should return expected object ref", func() {
// 				actualRef, err := conn.DeleteObject(ref)

// 				Expect(err).To(BeNil())
// 				Expect(actualRef).To(Equal(expectRef))
// 			})

// 		})

// 		Describe("GetObject", func() {
// 			netviewName := "private-view"
// 			eaKey := "CMP Type"
// 			eaVal := "OpenStack"
// 			netViewObj := NewNetworkView(NetworkView{
// 				Name: netviewName,
// 				Ea:   EA{eaKey: eaVal},
// 			})

// 			requestType := RequestType(GET)
// 			eaStr := `"extattrs":{"` + eaKey + `":{"value":"` + eaVal + `"}}`
// 			netviewStr := `"network_view":"` + netviewName + `"`
// 			urlStr := fmt.Sprintf("https://%s:%s/wapi/v%s/%s",
// 				host, port, version, netViewObj.ObjectType())
// 			bodyStr := []byte("{" + strings.Join([]string{netviewStr, eaStr}, ",") + "}")
// 			httpReq, _ := http.NewRequest(requestType.toMethod(), urlStr, bytes.NewBuffer(bodyStr))
// 			frb := &FakeRequestBuilder{
// 				r:   requestType,
// 				obj: netViewObj,
// 				ref: "",

// 				urlStr:  urlStr,
// 				bodyStr: bodyStr,
// 				req:     httpReq,
// 			}

// 			expectRef := "networkview/ZG5zLm5ldHdvcmtfdmlldyQyMw:global_view/false"
// 			expectObj := NewNetworkView(NetworkView{
// 				Ref:  expectRef,
// 				Name: netviewName,
// 				Ea:   EA{eaKey: eaVal},
// 			})
// 			expectRes, _ := json.Marshal(expectObj)

// 			fhr := &FakeHttpRequestor{
// 				config: transportConfig,

// 				req: httpReq,
// 				res: expectRes,
// 			}

// 			OrigValidateConnector := ValidateConnector
// 			ValidateConnector = MockValidateConnector
// 			defer func() { ValidateConnector = OrigValidateConnector }()

// 			conn, err := NewConnector(hostConfig, transportConfig,
// 				frb, fhr)

// 			if err != nil {
// 				Fail("Error creating Connector")
// 			}
// 			It("should return expected object", func() {
// 				actual := &NetworkView{}
// 				err := conn.GetObject(netViewObj, "", actual)
// 				Expect(err).To(BeNil())
// 				Expect(NewNetworkView(*actual)).To(Equal(expectObj))
// 			})
// 		})
// 		Describe("makeRequest", func() {
// 			Context("for GET request", func() {
// 				netviewName := "private-view"
// 				eaKey := "CMP Type"
// 				eaVal := "OpenStack"
// 				ref := ""
// 				var queryParams QueryParams
// 				netViewObj := NewNetworkView(NetworkView{
// 					Name: netviewName,
// 					Ea:   EA{eaKey: eaVal},
// 				})

// 				requestType := RequestType(GET)
// 				eaStr := `"extattrs":{"` + eaKey + `":{"value":"` + eaVal + `"}}`
// 				netviewStr := `"network_view":"` + netviewName + `"`
// 				urlStr := fmt.Sprintf("https://%s:%s/wapi/v%s/%s",
// 					host, port, version, netViewObj.ObjectType())

// 				bodyStr := []byte("{" + strings.Join([]string{netviewStr, eaStr}, ",") + "}")
// 				httpReq, _ := http.NewRequest(requestType.toMethod(), urlStr, bytes.NewBuffer(bodyStr))
// 				frb := &FakeRequestBuilder{
// 					r:   requestType,
// 					obj: netViewObj,
// 					ref: "",

// 					urlStr:  urlStr,
// 					bodyStr: bodyStr,
// 					req:     httpReq,
// 				}

// 				expectRef := "networkview/ZG5zLm5ldHdvcmtfdmlldyQyMw:global_view/false"
// 				expectObj := NewNetworkView(NetworkView{
// 					Ref:  expectRef,
// 					Name: netviewName,
// 					Ea:   EA{eaKey: eaVal},
// 				})
// 				expectRes, _ := json.Marshal(expectObj)

// 				fhr := &FakeHttpRequestor{
// 					config: transportConfig,

// 					req: httpReq,
// 					res: expectRes,
// 				}

// 				OrigValidateConnector := ValidateConnector
// 				ValidateConnector = MockValidateConnector
// 				defer func() { ValidateConnector = OrigValidateConnector }()

// 				conn, err := NewConnector(hostConfig, transportConfig,
// 					frb, fhr)

// 				if err != nil {
// 					Fail("Error creating Connector")
// 				}
// 				actual := &NetworkView{}
// 				It("should return expected object when forceProxy is false", func() {
// 					queryParams.forceProxy = false //disable proxy
// 					res, err := conn.makeRequest(GET, netViewObj, ref, queryParams)
// 					err = json.Unmarshal(res, &actual)
// 					Expect(err).To(BeNil())
// 					Expect(NewNetworkView(*actual)).To(Equal(expectObj))
// 				})
// 				It("should return expected object when forceProxy is true", func() {
// 					queryParams.forceProxy = true //disable proxy
// 					res, err := conn.makeRequest(GET, netViewObj, ref, queryParams)
// 					err = json.Unmarshal(res, &actual)
// 					Expect(err).To(BeNil())
// 					Expect(NewNetworkView(*actual)).To(Equal(expectObj))
// 				})
// 			})

// 		})

// 	})
// })
