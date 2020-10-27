package types

// ==================== //
// == Network Policy == //
// ==================== //

// SpecCIDR Structure
type SpecCIDR struct {
	CIDR   string   `json:"cidr" yaml:"cidr"`
	Except []string `json:"except" yaml:"except"`
}

// SpecPort Structure
type SpecPort struct {
	Ports    string `json:"ports" yaml:"ports"`
	Protocol string `json:"protocol" yaml:"protocol"`
}

// SpecService Structure
type SpecService struct {
	ServiceName string `json:"service_name" yaml:"service_name"`
	Namespace   string `json:"namespace" yaml:"namespace"`
}

// SpecFQDN Structure
type SpecFQDN struct {
	Name string `json:"name" yaml:"name"`
}

// SpecHTTP Structure
type SpecHTTP struct {
	Method string `json:"method" yaml:"method"`
	Path   string `json:"path" yaml:"path"`
}

// PolicyNetwork Structure
type PolicyNetwork struct {
	HostIP string `json:"host_ip" yaml:"host_ip"`

	BridgeIP  string `json:"bridge_ip" yaml:"bridge_ip"`
	BridgeMac string `json:"bridge_mac" yaml:"bridge_mac"`

	IP      string `json:"ip" yaml:"ip"`
	Mac     string `json:"mac" yaml:"mac"`
	VEthIdx int    `json:"veth_idx" yaml:"veth_idx"`
}

// Selector Structure
type Selector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty"`
}

// Ingress Structure
type Ingress struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty"`

	FromEntities []string `json:"fromEntities,omitempty" yaml:"fromEntities,omitempty"`

	FromCIDRs    []SpecCIDR    `json:"fromCIDRs,omitempty" yaml:"fromCIDRs,omitempty"`
	FromPorts    []SpecPort    `json:"fromPorts,omitempty" yaml:"fromPorts,omitempty"`
	FromServices []SpecService `json:"fromServices,omitempty" yaml:"fromServices,omitempty"`
}

// Egress Structure
type Egress struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty"`

	ToEndtities []string `json:"toEntities,omitempty" yaml:"toEntities,omitempty"`

	ToCIDRs    []SpecCIDR    `json:"toCIDRs,omitempty" yaml:"toCIDRs,omitempty"`
	ToPorts    []SpecPort    `json:"toPorts,omitempty" yaml:"toPorts,omitempty"`
	ToServices []SpecService `json:"toServices,omitempty" yaml:"toServices,omitempty"`
}

// Spec Structure
type Spec struct {
	Selector Selector `json:"selector,omitempty" yaml:"selector,omitempty"`
	Ingress  Ingress  `json:"ingress,omitempty" yaml:"ingress,omitempty"`
	Egress   Egress   `json:"egress,omitempty" yaml:"egress,omitempty"`

	Action string `json:"action,omitempty" yaml:"action,omitempty"`
}

// KnoxNetworkPolicy Structure
type KnoxNetworkPolicy struct {
	APIVersion    string            `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	Kind          string            `json:"kind,omitempty" yaml:"kind,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Spec          Spec              `json:"spec,omitempty" yaml:"spec,omitempty"`
	GeneratedTime int64             `json:"generated_time,omitempty" yaml:"generated_time,omitempty"`
}

// =========================== //
// == Cilium Network Policy == //
// =========================== //

// CiliumCIDRSet Structure
type CiliumCIDRSet struct {
	CIDR   string   `json:"cidr" yaml:"cidr"`
	Except []string `json:"except,omitempty" yaml:"except,omitempty"`
}

// CiliumPort Structure
type CiliumPort struct {
	Port     string `json:"port,omitempty" yaml:"port,omitempty"`
	Protocol string `json:"protocol" yaml:"protocol"`
}

// CiliumPortList Structure
type CiliumPortList struct {
	Ports []CiliumPort `json:"ports,omitempty" yaml:"ports,omitempty"`
}

// CiliumEndpoints Structure
type CiliumEndpoints struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty"`
}

// CiliumK8sService Structure
type CiliumK8sService struct {
	ServiceName string `json:"serviceName,omitempty" yaml:"serviceName,omitempty"`
	Namespace   string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
}

// CiliumService Structure
type CiliumService struct {
	K8sService []CiliumK8sService `json:"k8sService,omitempty" yaml:"k8sService,omitempty"`
}

// CiliumEgress Structure
type CiliumEgress struct {
	ToEndpoints []CiliumEndpoints `json:"toEndpoints,omitempty" yaml:"toEndpoints,omitempty"`
	ToEndtities []string          `json:"toEntities,omitempty" yaml:"toEntities,omitempty"`
	ToPorts     []CiliumPortList  `json:"toPorts,omitempty" yaml:"toPorts,omitempty"`
	ToCIDRs     []string          `json:"toCIDRs,omitempty" yaml:"toCIDRs,omitempty"`
	ToServices  []CiliumService   `json:"toServices,omitempty" yaml:"toServices,omitempty"`
}

// CiliumIngress Structure
type CiliumIngress struct {
	FromEndpoints []CiliumEndpoints `json:"fromEndpoints,omitempty" yaml:"fromEndpoints,omitempty"`
	FromEntities  []string          `json:"fromEntities,omitempty" yaml:"fromEntities,omitempty"`

	FromPorts []CiliumPortList `json:"fromPorts,omitempty" yaml:"fromPorts,omitempty"`
	FromCIDRs []string         `json:"fromCIDRs,omitempty" yaml:"fromCIDRs,omitempty"`
}

// CiliumSpec Structure
type CiliumSpec struct {
	Selector Selector `json:"endpointSelector,omitempty" yaml:"endpointSelector,omitempty"`

	Egress  []CiliumEgress  `json:"egress,omitempty" yaml:"egress,omitempty"`
	Ingress []CiliumIngress `json:"ingress,omitempty" yaml:"ingress,omitempty"`
}

// CiliumNetworkPolicy Structure
type CiliumNetworkPolicy struct {
	APIVersion string            `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty" yaml:"kind,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Spec       CiliumSpec        `json:"spec" yaml:"spec"`
}

// ========================== //
// == Service Chain Policy == //
// ========================== //

// ServiceChainSpec Structure
type ServiceChainSpec struct {
	Chains []string `json:"chains,omitempty" yaml:"chains,omitempty"`
}

// ServiceChainPolicy Structure
type ServiceChainPolicy struct {
	UpdatedTime string `json:"updated_time" yaml:"updated_time"`

	ID uint32 `json:"id,omitempty" yaml:"id,omitempty"`

	APIVersion string            `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty" yaml:"kind,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Priority   int               `json:"priority" yaml:"priority"`
	Spec       ServiceChainSpec  `json:"spec" yaml:"spec"`
}

// =================== //
// == System Policy == //
// =================== //

// Process Structure
type Process struct {
	MatchNames []string `json:"matchNames,omitempty" yaml:"matchNames,omitempty"`
	MatchPaths []string `json:"matchPaths,omitempty" yaml:"matchPaths,omitempty"`
}

// File Structure
type File struct {
	MatchNames       []string `json:"matchNames,omitempty" yaml:"matchNames,omitempty"`
	MatchPaths       []string `json:"matchPaths,omitempty" yaml:"matchPaths,omitempty"`
	MatchDirectories []string `json:"matchDirectories,omitempty" yaml:"matchDirectories,omitempty"`
}

// SystemSpec Structure
type SystemSpec struct {
	Selector Selector `json:"selector" yaml:"selector"`
	Process  Process  `json:"process" yaml:"process"`
	File     File     `json:"file" yaml:"file"`

	Action string `json:"action,omitempty" yaml:"action,omitempty"`
}

// SystemPolicy Structure
type SystemPolicy struct {
	UpdatedTime string `json:"updated_time" yaml:"updated_time"`

	ID uint32 `json:"id,omitempty" yaml:"id,omitempty"`

	APIVersion string            `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty" yaml:"kind,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Priority   int               `json:"priority" yaml:"priority"`
	Spec       SystemSpec        `json:"spec" yaml:"spec"`

	PolicyType int // set in system monitor
}
