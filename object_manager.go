package ibclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// IBObjectManager defines the what???
type IBObjectManager interface {
	AllocateIP(netview string, cidr string, ipAddr string, macAddress string, name string, ea EA) (*FixedAddress, error)
	AllocateNetwork(netview string, cidr string, prefixLen uint, name string) (network *Network, err error)
	CreateARecord(netview string, dnsview string, recordname string, cidr string, ipAddr string, ea EA) (*RecordA, error)
	CreateZoneAuth(fqdn string, ea EA) (*ZoneAuth, error)
	CreateCNAMERecord(canonical string, recordname string, dnsview string, ea EA) (*RecordCNAME, error)
	CreateDefaultNetviews(globalNetview string, localNetview string) (globalNetviewRef string, localNetviewRef string, err error)
	CreateEADefinition(eadef EADefinition) (*EADefinition, error)
	CreateHostRecord(enabledns bool, recordName string, netview string, dnsview string, cidr string, ipAddr string, macAddress string, ea EA) (*HostRecord, error)
	CreateNetwork(netview string, cidr string, name string) (*Network, error)
	CreateNetworkContainer(netview string, cidr string) (*NetworkContainer, error)
	CreateNetworkView(name string) (*NetworkView, error)
	CreatePTRRecord(netview string, dnsview string, recordname string, cidr string, ipAddr string, ea EA) (*RecordPTR, error)
	DeleteARecord(ref string) (string, error)
	DeleteZoneAuth(ref string) (string, error)
	DeleteCNAMERecord(ref string) (string, error)
	DeleteFixedAddress(ref string) (string, error)
	DeleteHostRecord(ref string) (string, error)
	DeleteNetwork(ref string, netview string) (string, error)
	DeleteNetworkView(ref string) (string, error)
	DeletePTRRecord(ref string) (string, error)
	GetARecordByRef(ref string) (*RecordA, error)
	GetCNAMERecordByRef(ref string) (*RecordA, error)
	GetEADefinition(name string) (*EADefinition, error)
	GetFixedAddress(netview string, cidr string, ipAddr string, macAddr string) (*FixedAddress, error)
	GetFixedAddressByRef(ref string) (*FixedAddress, error)
	GetHostRecord(recordName string) (*HostRecord, error)
	GetHostRecordByRef(ref string) (*HostRecord, error)
	GetIpAddressFromHostRecord(host HostRecord) (string, error)
	GetNetwork(netview string, cidr string, ea EA) (*Network, error)
	GetNetworkContainer(netview string, cidr string) (*NetworkContainer, error)
	GetNetworkView(name string) (*NetworkView, error)
	GetPTRRecordByRef(ref string) (*RecordPTR, error)
	GetZoneAuthByRef(ref string) (*ZoneAuth, error)
	ReleaseIP(netview string, cidr string, ipAddr string, macAddr string) (string, error)
	UpdateFixedAddress(fixedAddrRef string, matchclient string, macAddress string, vmID string, vmName string) (*FixedAddress, error)
	UpdateHostRecord(hostRref string, ipAddr string, macAddress string, vmID string, vmName string) (string, error)
	UpdateNetworkViewEA(ref string, addEA EA, removeEA EA) error
}

// ObjectManager what?
type ObjectManager struct {
	connector IBConnector
	cmpType   string
	tenantID  string
	// If OmitCloudAttrs is true no extra attributes for cloud are set
	OmitCloudAttrs bool
}

// NewObjectManager returns an ObjectManager configured with ...
func NewObjectManager(connector IBConnector, cmpType string, tenantID string) *ObjectManager {
	objMgr := new(ObjectManager)

	objMgr.connector = connector
	objMgr.cmpType = cmpType
	objMgr.tenantID = tenantID

	return objMgr
}

func (objMgr *ObjectManager) getBasicEA(cloudAPIOwned Bool) EA {
	ea := make(EA)
	if !objMgr.OmitCloudAttrs {
		ea["Cloud API Owned"] = cloudAPIOwned
		ea["CMP Type"] = objMgr.cmpType
		ea["Tenant ID"] = objMgr.tenantID
	}
	return ea
}

func (objMgr *ObjectManager) extendEA(ea EA) EA {
	eas := objMgr.getBasicEA(true)
	for k, v := range ea {
		eas[k] = v
	}
	return eas
}

// CreateNetworkView https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) CreateNetworkView(name string) (*NetworkView, error) {
	networkView := NewNetworkView(NetworkView{
		Name: name,
		Ea:   objMgr.getBasicEA(false)})

	ref, err := objMgr.connector.CreateObject(networkView)
	networkView.Ref = ref

	return networkView, err
}

func (objMgr *ObjectManager) makeNetworkView(netviewName string) (netviewRef string, err error) {
	var netviewObj *NetworkView
	if netviewObj, err = objMgr.GetNetworkView(netviewName); err != nil {
		return
	}
	if netviewObj == nil {
		if netviewObj, err = objMgr.CreateNetworkView(netviewName); err != nil {
			return
		}
	}

	netviewRef = netviewObj.Ref

	return
}

// CreateDefaultNetviews https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) CreateDefaultNetviews(globalNetview string, localNetview string) (globalNetviewRef string, localNetviewRef string, err error) {
	if globalNetviewRef, err = objMgr.makeNetworkView(globalNetview); err != nil {
		return
	}

	if localNetviewRef, err = objMgr.makeNetworkView(localNetview); err != nil {
		return
	}

	return
}

// CreateNetwork https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) CreateNetwork(netview string, cidr string, name string) (*Network, error) {
	network := NewNetwork(Network{
		NetviewName: netview,
		Cidr:        cidr,
		Ea:          objMgr.getBasicEA(true)})

	if name != "" {
		network.Ea["Network Name"] = name
	}
	ref, err := objMgr.connector.CreateObject(network)
	if err != nil {
		return nil, err
	}
	network.Ref = ref

	return network, err
}

// CreateNetworkContainer https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) CreateNetworkContainer(netview string, cidr string) (*NetworkContainer, error) {
	container := NewNetworkContainer(NetworkContainer{
		NetviewName: netview,
		Cidr:        cidr,
		Ea:          objMgr.getBasicEA(true)})

	ref, err := objMgr.connector.CreateObject(container)
	container.Ref = ref

	return container, err
}

// GetNetworkView https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) GetNetworkView(name string) (*NetworkView, error) {
	var res []NetworkView

	netview := NewNetworkView(NetworkView{Name: name})

	err := objMgr.connector.GetObject(netview, "", &res)

	if err != nil || res == nil || len(res) == 0 {
		return nil, err
	}

	return &res[0], nil
}

// UpdateNetworkViewEA https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) UpdateNetworkViewEA(ref string, addEA EA, removeEA EA) error {
	var res NetworkView

	nv := NetworkView{}
	nv.returnFields = []string{"extattrs"}
	err := objMgr.connector.GetObject(&nv, ref, &res)

	if err != nil {
		return err
	}

	for k, v := range addEA {
		res.Ea[k] = v
	}

	for k := range removeEA {
		_, ok := res.Ea[k]
		if ok {
			delete(res.Ea, k)
		}
	}

	_, err = objMgr.connector.UpdateObject(&res, ref)
	return err
}

// BuildNetworkViewFromRef https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func BuildNetworkViewFromRef(ref string) *NetworkView {
	// networkview/ZG5zLm5ldHdvcmtfdmlldyQyMw:global_view/false
	r := regexp.MustCompile(`networkview/\w+:([^/]+)/\w+`)
	m := r.FindStringSubmatch(ref)

	if m == nil {
		return nil
	}

	return &NetworkView{
		Ref:  ref,
		Name: m[1],
	}
}

// BuildNetworkFromRef https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func BuildNetworkFromRef(ref string) *Network {
	// network/ZG5zLm5ldHdvcmskODkuMC4wLjAvMjQvMjU:89.0.0.0/24/global_view
	r := regexp.MustCompile(`network/\w+:(\d+\.\d+\.\d+\.\d+/\d+)/(.+)`)
	m := r.FindStringSubmatch(ref)

	if m == nil {
		return nil
	}

	return &Network{
		Ref:         ref,
		NetviewName: m[2],
		Cidr:        m[1],
	}
}

// GetNetwork https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) GetNetwork(netview string, cidr string, ea EA) (*Network, error) {
	var res []Network

	network := NewNetwork(Network{
		NetviewName: netview})

	if cidr != "" {
		network.Cidr = cidr
	}

	if ea != nil && len(ea) > 0 {
		network.eaSearch = EASearch(ea)
	}

	err := objMgr.connector.GetObject(network, "", &res)

	if err != nil || res == nil || len(res) == 0 {
		return nil, err
	}

	return &res[0], nil
}

// GetNetworkwithref https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) GetNetworkwithref(ref string) (*Network, error) {
	network := NewNetwork(Network{})
	err := objMgr.connector.GetObject(network, ref, &network)
	return network, err
}

// GetNetworkContainer https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) GetNetworkContainer(netview string, cidr string) (*NetworkContainer, error) {
	var res []NetworkContainer

	nwcontainer := NewNetworkContainer(NetworkContainer{
		NetviewName: netview,
		Cidr:        cidr})

	err := objMgr.connector.GetObject(nwcontainer, "", &res)

	if err != nil || res == nil || len(res) == 0 {
		return nil, err
	}

	return &res[0], nil
}

// GetIPAddressFromRef https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func GetIPAddressFromRef(ref string) string {
	// fixedaddress/ZG5zLmJpbmRfY25h:12.0.10.1/external
	r := regexp.MustCompile(`fixedaddress/\w+:(\d+\.\d+\.\d+\.\d+)/.+`)
	m := r.FindStringSubmatch(ref)

	if m != nil {
		return m[1]
	}
	return ""
}

// AllocateIP https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) AllocateIP(netview string, cidr string, ipAddr string, macAddress string, name string, ea EA) (*FixedAddress, error) {
	if len(macAddress) == 0 {
		macAddress = "00:00:00:00:00:00"
	}

	eas := objMgr.extendEA(ea)

	fixedAddr := NewFixedAddress(FixedAddress{
		NetviewName: netview,
		Cidr:        cidr,
		Mac:         macAddress,
		Name:        name,
		Ea:          eas})

	if ipAddr == "" {
		fixedAddr.IPAddress = fmt.Sprintf("func:nextavailableip:%s,%s", cidr, netview)
	} else {
		fixedAddr.IPAddress = ipAddr
	}

	ref, err := objMgr.connector.CreateObject(fixedAddr)
	fixedAddr.Ref = ref
	fixedAddr.IPAddress = GetIPAddressFromRef(ref)

	return fixedAddr, err
}

// AllocateNetwork https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) AllocateNetwork(netview string, cidr string, prefixLen uint, name string) (network *Network, err error) {
	network = nil

	networkReq := NewNetwork(Network{
		NetviewName: netview,
		Cidr:        fmt.Sprintf("func:nextavailablenetwork:%s,%s,%d", cidr, netview, prefixLen),
		Ea:          objMgr.getBasicEA(true)})
	if name != "" {
		networkReq.Ea["Network Name"] = name
	}

	ref, err := objMgr.connector.CreateObject(networkReq)
	if err == nil && len(ref) > 0 {
		network = BuildNetworkFromRef(ref)
	}

	return
}

// GetFixedAddress https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) GetFixedAddress(netview string, cidr string, ipAddr string, macAddr string) (*FixedAddress, error) {
	var res []FixedAddress

	fixedAddr := NewFixedAddress(FixedAddress{
		NetviewName: netview,
		Cidr:        cidr,
		IPAddress:   ipAddr})

	if macAddr != "" {
		fixedAddr.Mac = macAddr
	}

	err := objMgr.connector.GetObject(fixedAddr, "", &res)

	if err != nil || res == nil || len(res) == 0 {
		return nil, err
	}

	return &res[0], nil
}

// GetFixedAddressByRef https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) GetFixedAddressByRef(ref string) (*FixedAddress, error) {
	fixedAddr := NewFixedAddress(FixedAddress{})
	err := objMgr.connector.GetObject(fixedAddr, ref, &fixedAddr)
	return fixedAddr, err
}

// DeleteFixedAddress https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) DeleteFixedAddress(ref string) (string, error) {
	return objMgr.connector.DeleteObject(ref)
}

// validation  for match_client
func validateMatchClient(value string) bool {
	matchClient := [5]string{"MAC_ADDRESS", "CLIENT_ID", "RESERVED", "CIRCUIT_ID", "REMOTE_ID"}

	for _, val := range matchClient {
		if val == value {
			return true
		}
	}
	return false
}

// UpdateFixedAddress https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) UpdateFixedAddress(fixedAddrRef string, matchClient string, macAddress string, vmID string, vmName string) (*FixedAddress, error) {
	updateFixedAddr := NewFixedAddress(FixedAddress{Ref: fixedAddrRef})

	if len(macAddress) != 0 {
		updateFixedAddr.Mac = macAddress
	}

	ea := objMgr.getBasicEA(true)
	if vmID != "" {
		ea["VM ID"] = vmID
		updateFixedAddr.Ea = ea
	}
	if vmName != "" {
		ea["VM Name"] = vmName
		updateFixedAddr.Ea = ea
	}
	if matchClient != "" {
		if validateMatchClient(matchClient) {
			updateFixedAddr.MatchClient = matchClient
		} else {
			return nil, fmt.Errorf("wrong value for match_client passed %s \n ", matchClient)
		}
	}

	refResp, err := objMgr.connector.UpdateObject(updateFixedAddr, fixedAddrRef)
	updateFixedAddr.Ref = refResp
	return updateFixedAddr, err
}

// ReleaseIP https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) ReleaseIP(netview string, cidr string, ipAddr string, macAddr string) (string, error) {
	fixAddress, _ := objMgr.GetFixedAddress(netview, cidr, ipAddr, macAddr)
	if fixAddress == nil {
		return "", nil
	}
	return objMgr.connector.DeleteObject(fixAddress.Ref)
}

// DeleteNetwork https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) DeleteNetwork(ref string, netview string) (string, error) {
	network := BuildNetworkFromRef(ref)
	if network != nil && network.NetviewName == netview {
		return objMgr.connector.DeleteObject(ref)
	}

	return "", nil
}

// DeleteNetworkView https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) DeleteNetworkView(ref string) (string, error) {
	return objMgr.connector.DeleteObject(ref)
}

// GetEADefinition https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) GetEADefinition(name string) (*EADefinition, error) {
	var res []EADefinition

	eadef := NewEADefinition(EADefinition{Name: name})

	err := objMgr.connector.GetObject(eadef, "", &res)

	if err != nil || res == nil || len(res) == 0 {
		return nil, err
	}

	return &res[0], nil
}

// CreateEADefinition https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) CreateEADefinition(eadef EADefinition) (*EADefinition, error) {
	newEadef := NewEADefinition(eadef)

	ref, err := objMgr.connector.CreateObject(newEadef)
	newEadef.Ref = ref

	return newEadef, err
}

// CreateHostRecord https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) CreateHostRecord(enabledns bool, recordName string, netview string, dnsview string, cidr string, ipAddr string, macAddress string, ea EA) (*HostRecord, error) {

	eas := objMgr.extendEA(ea)

	recordHostIPAddr := NewHostRecordIpv4Addr(HostRecordIpv4Addr{Mac: macAddress})

	if ipAddr == "" {
		recordHostIPAddr.Ipv4Addr = fmt.Sprintf("func:nextavailableip:%s,%s", cidr, netview)
	} else {
		recordHostIPAddr.Ipv4Addr = ipAddr
	}
	enableDNS := new(bool)
	*enableDNS = enabledns
	recordHostIPAddrSlice := []HostRecordIpv4Addr{*recordHostIPAddr}
	recordHost := NewHostRecord(HostRecord{
		Name:        recordName,
		EnableDNS:   enableDNS,
		NetworkView: netview,
		View:        dnsview,
		Ipv4Addrs:   recordHostIPAddrSlice,
		Ea:          eas})

	ref, err := objMgr.connector.CreateObject(recordHost)
	if err != nil {
		return nil, err
	}
	recordHost.Ref = ref
	err = objMgr.connector.GetObject(recordHost, ref, &recordHost)
	return recordHost, err
}

// GetHostRecordByRef https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) GetHostRecordByRef(ref string) (*HostRecord, error) {
	recordHost := NewHostRecord(HostRecord{})
	err := objMgr.connector.GetObject(recordHost, ref, &recordHost)
	return recordHost, err
}

// GetHostRecord https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) GetHostRecord(recordName string) (*HostRecord, error) {
	var res []HostRecord

	recordHost := NewHostRecord(HostRecord{})
	if recordName != "" {
		recordHost.Name = recordName
	}

	err := objMgr.connector.GetObject(recordHost, "", &res)

	if err != nil || res == nil || len(res) == 0 {
		return nil, err
	}
	return &res[0], err

}

// GetIPAddressFromHostRecord https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) GetIPAddressFromHostRecord(host HostRecord) (string, error) {
	err := objMgr.connector.GetObject(&host, host.Ref, &host)
	return host.Ipv4Addrs[0].Ipv4Addr, err
}

// UpdateHostRecord https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) UpdateHostRecord(hostRref string, ipAddr string, macAddress string, vmID string, vmName string) (string, error) {

	recordHostIPAddr := NewHostRecordIpv4Addr(HostRecordIpv4Addr{Mac: macAddress, Ipv4Addr: ipAddr})
	recordHostIPAddrSlice := []HostRecordIpv4Addr{*recordHostIPAddr}
	updateHostRecord := NewHostRecord(HostRecord{Ipv4Addrs: recordHostIPAddrSlice})

	ea := objMgr.getBasicEA(true)
	if vmID != "" {
		ea["VM ID"] = vmID
		updateHostRecord.Ea = ea
	}

	if vmName != "" {
		ea["VM Name"] = vmName
		updateHostRecord.Ea = ea
	}
	ref, err := objMgr.connector.UpdateObject(updateHostRecord, hostRref)
	return ref, err
}

// DeleteHostRecord https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) DeleteHostRecord(ref string) (string, error) {
	return objMgr.connector.DeleteObject(ref)
}

// CreateARecord https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) CreateARecord(netview string, dnsview string, recordname string, cidr string, ipAddr string, ea EA) (*RecordA, error) {

	eas := objMgr.extendEA(ea)

	recordA := NewRecordA(RecordA{
		View: dnsview,
		Name: recordname,
		Ea:   eas})

	if ipAddr == "" {
		recordA.Ipv4Addr = fmt.Sprintf("func:nextavailableip:%s,%s", cidr, netview)
	} else {
		recordA.Ipv4Addr = ipAddr
	}
	ref, err := objMgr.connector.CreateObject(recordA)
	recordA.Ref = ref
	return recordA, err
}

// GetARecordByRef https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) GetARecordByRef(ref string) (*RecordA, error) {
	recordA := NewRecordA(RecordA{})
	err := objMgr.connector.GetObject(recordA, ref, &recordA)
	return recordA, err
}

// DeleteARecord https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) DeleteARecord(ref string) (string, error) {
	return objMgr.connector.DeleteObject(ref)
}

// CreateCNAMERecord https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) CreateCNAMERecord(canonical string, recordname string, dnsview string, ea EA) (*RecordCNAME, error) {

	eas := objMgr.extendEA(ea)

	recordCNAME := NewRecordCNAME(RecordCNAME{
		View:      dnsview,
		Name:      recordname,
		Canonical: canonical,
		Ea:        eas})

	ref, err := objMgr.connector.CreateObject(recordCNAME)
	recordCNAME.Ref = ref
	return recordCNAME, err
}

// GetCNAMERecordByRef https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) GetCNAMERecordByRef(ref string) (*RecordCNAME, error) {
	recordCNAME := NewRecordCNAME(RecordCNAME{})
	err := objMgr.connector.GetObject(recordCNAME, ref, &recordCNAME)
	return recordCNAME, err
}

// DeleteCNAMERecord https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) DeleteCNAMERecord(ref string) (string, error) {
	return objMgr.connector.DeleteObject(ref)
}

// CreateTXTRecord creates TXT Record. Use TTL of 0 to inherit TTL from the Zone
func (objMgr *ObjectManager) CreateTXTRecord(recordname string, text string, ttl int, dnsview string) (*RecordTXT, error) {

	recordTXT := NewRecordTXT(RecordTXT{
		View: dnsview,
		Name: recordname,
		Text: text,
		TTL:  ttl,
	})

	ref, err := objMgr.connector.CreateObject(recordTXT)
	recordTXT.Ref = ref
	return recordTXT, err
}

// GetTXTRecordByRef https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) GetTXTRecordByRef(ref string) (*RecordTXT, error) {
	recordTXT := NewRecordTXT(RecordTXT{})
	err := objMgr.connector.GetObject(recordTXT, ref, &recordTXT)
	return recordTXT, err
}

// GetTXTRecord https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) GetTXTRecord(name string) (*RecordTXT, error) {
	if name == "" {
		return nil, fmt.Errorf("name can not be empty")
	}
	var res []RecordTXT

	recordTXT := NewRecordTXT(RecordTXT{Name: name})

	err := objMgr.connector.GetObject(recordTXT, "", &res)

	if err != nil || res == nil || len(res) == 0 {
		return nil, err
	}

	return &res[0], nil
}

// UpdateTXTRecord https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) UpdateTXTRecord(recordname string, text string) (*RecordTXT, error) {
	var res []RecordTXT

	recordTXT := NewRecordTXT(RecordTXT{Name: recordname})

	err := objMgr.connector.GetObject(recordTXT, "", &res)

	if err != nil || len(res) == 0 {
		return nil, err
	}

	res[0].Text = text

	res[0].Zone = "" //  set the Zone value to "" as its a non writable field

	_, err = objMgr.connector.UpdateObject(&res[0], res[0].Ref)

	if err != nil || res == nil || len(res) == 0 {
		return nil, err
	}

	return &res[0], nil
}

// DeleteTXTRecord https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) DeleteTXTRecord(ref string) (string, error) {
	return objMgr.connector.DeleteObject(ref)
}

// CreatePTRRecord https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) CreatePTRRecord(netview string, dnsview string, recordname string, cidr string, ipAddr string, ea EA) (*RecordPTR, error) {

	eas := objMgr.extendEA(ea)

	recordPTR := NewRecordPTR(RecordPTR{
		View:     dnsview,
		PtrdName: recordname,
		Ea:       eas})

	if ipAddr == "" {
		recordPTR.Ipv4Addr = fmt.Sprintf("func:nextavailableip:%s,%s", cidr, netview)
	} else {
		recordPTR.Ipv4Addr = ipAddr
	}
	ref, err := objMgr.connector.CreateObject(recordPTR)
	recordPTR.Ref = ref
	return recordPTR, err
}

// GetPTRRecordByRef https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) GetPTRRecordByRef(ref string) (*RecordPTR, error) {
	recordPTR := NewRecordPTR(RecordPTR{})
	err := objMgr.connector.GetObject(recordPTR, ref, &recordPTR)
	return recordPTR, err
}

// DeletePTRRecord https://github.com/infobloxopen/infoblox-swagger-wapi/issues/1
func (objMgr *ObjectManager) DeletePTRRecord(ref string) (string, error) {
	return objMgr.connector.DeleteObject(ref)
}

// CreateMultiObject unmarshals the result into slice of maps
func (objMgr *ObjectManager) CreateMultiObject(req *MultiRequest) ([]map[string]interface{}, error) {

	conn := objMgr.connector.(*Connector)
	queryParams := QueryParams{forceProxy: false}
	res, err := conn.makeRequest(CREATE, req, "", queryParams)

	if err != nil {
		return nil, err
	}

	var result []map[string]interface{}
	err = json.Unmarshal(res, &result)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetUpgradeStatus returns the grid upgrade information
func (objMgr *ObjectManager) GetUpgradeStatus(statusType string) ([]UpgradeStatus, error) {
	var res []UpgradeStatus

	if statusType == "" {
		// TODO option may vary according to the WAPI version, need to
		// throw relevant  error.
		msg := "Status type can not be nil"
		return res, errors.New(msg)
	}
	upgradestatus := NewUpgradeStatus(UpgradeStatus{Type: statusType})
	err := objMgr.connector.GetObject(upgradestatus, "", &res)

	return res, err
}

// GetAllMembers returns all members information
func (objMgr *ObjectManager) GetAllMembers() ([]Member, error) {
	var res []Member

	memberObj := NewMember(Member{})
	err := objMgr.connector.GetObject(memberObj, "", &res)
	return res, err
}

// GetCapacityReport returns all capacity for members
func (objMgr *ObjectManager) GetCapacityReport(name string) ([]CapacityReport, error) {
	var res []CapacityReport

	capacityObj := CapacityReport{Name: name}
	capacityReport := NewCapcityReport(capacityObj)
	err := objMgr.connector.GetObject(capacityReport, "", &res)
	return res, err
}

// GetLicense returns the license details for member
func (objMgr *ObjectManager) GetLicense() ([]License, error) {
	var res []License

	licenseObj := NewLicense(License{})
	err := objMgr.connector.GetObject(licenseObj, "", &res)
	return res, err
}

// GetGridLicense returns the license details for grid
func (objMgr *ObjectManager) GetGridLicense() ([]License, error) {
	var res []License

	licenseObj := NewGridLicense(License{})
	err := objMgr.connector.GetObject(licenseObj, "", &res)
	return res, err
}

// GetGridInfo returns the details for grid
func (objMgr *ObjectManager) GetGridInfo() ([]Grid, error) {
	var res []Grid

	gridObj := NewGrid(Grid{})
	err := objMgr.connector.GetObject(gridObj, "", &res)
	return res, err
}

// CreateZoneAuth creates zones and subs by passing fqdn
func (objMgr *ObjectManager) CreateZoneAuth(fqdn string, ea EA) (*ZoneAuth, error) {

	eas := objMgr.extendEA(ea)

	zoneAuth := NewZoneAuth(ZoneAuth{
		Fqdn: fqdn,
		Ea:   eas})

	ref, err := objMgr.connector.CreateObject(zoneAuth)
	zoneAuth.Ref = ref
	return zoneAuth, err
}

// GetZoneAuthByRef retreives an authortative zone by ref
func (objMgr *ObjectManager) GetZoneAuthByRef(ref string) (ZoneAuth, error) {
	var res ZoneAuth

	if ref == "" {
		return res, nil
	}
	zoneAuth := NewZoneAuth(ZoneAuth{})

	err := objMgr.connector.GetObject(zoneAuth, ref, &res)
	return res, err
}

// DeleteZoneAuth deletes an auth zone
func (objMgr *ObjectManager) DeleteZoneAuth(ref string) (string, error) {
	return objMgr.connector.DeleteObject(ref)
}

// GetZoneAuth returns the authoritatives zones
func (objMgr *ObjectManager) GetZoneAuth() ([]ZoneAuth, error) {
	var res []ZoneAuth

	zoneAuth := NewZoneAuth(ZoneAuth{})
	err := objMgr.connector.GetObject(zoneAuth, "", &res)

	return res, err
}

// GetZoneDelegated returns the delegated zone
func (objMgr *ObjectManager) GetZoneDelegated(fqdn string) (*ZoneDelegated, error) {
	if len(fqdn) == 0 {
		return nil, nil
	}
	var res []ZoneDelegated

	zoneDelegated := NewZoneDelegated(ZoneDelegated{Fqdn: fqdn})

	err := objMgr.connector.GetObject(zoneDelegated, "", &res)

	if err != nil || res == nil || len(res) == 0 {
		return nil, err
	}

	return &res[0], nil
}

// CreateZoneDelegated creates delegated zone
func (objMgr *ObjectManager) CreateZoneDelegated(fqdn string, delegateTo []NameServer) (*ZoneDelegated, error) {
	zoneDelegated := NewZoneDelegated(ZoneDelegated{
		Fqdn:       fqdn,
		DelegateTo: delegateTo})

	ref, err := objMgr.connector.CreateObject(zoneDelegated)
	zoneDelegated.Ref = ref

	return zoneDelegated, err
}

// UpdateZoneDelegated updates delegated zone
func (objMgr *ObjectManager) UpdateZoneDelegated(ref string, delegateTo []NameServer) (*ZoneDelegated, error) {
	zoneDelegated := NewZoneDelegated(ZoneDelegated{
		Ref:        ref,
		DelegateTo: delegateTo})

	refResp, err := objMgr.connector.UpdateObject(zoneDelegated, ref)
	zoneDelegated.Ref = refResp
	return zoneDelegated, err
}

// DeleteZoneDelegated deletes delegated zone
func (objMgr *ObjectManager) DeleteZoneDelegated(ref string) (string, error) {
	return objMgr.connector.DeleteObject(ref)
}
