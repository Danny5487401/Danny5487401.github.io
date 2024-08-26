---
title: "资源注册表(scheme)"
date: 2024-08-26T15:44:47+08:00
draft: true
summary: kubernetes 资源管理的核心数据结构schema, 版本转换
---
# schema 
Kubernetes 的 API Schema 是对集群资源的规范定义和元数据的集合，它在 Kubernetes 集群的管理和操作中起着至关重要的作用。简单来说，Schema 可以被理解为一种定义和约束集群资源结构的标准方式。
通过使用 Schema，Kubernetes 可以确保集群中的各种资源具有一致的结构和属性，从而方便了资源的创建、修改和查询等操作

{{<figure src="./apiserver-schema.png#center" width=800px >}}
Kubernetes 将资源拆分为三类，并且由三种 HTTP Server 负责处理这三类资源。

三类资源分别注册到 extensionsapiserver.Scheme，legacyscheme.Scheme 和 aggregatorscheme.Scheme 三种资源注册表中

## 为什么需要Scheme
因为在web开发中随着版本的更新迭代,通常要在系统中维护多个版本的api,多个版本的api在数据结构上往往也各不相同

{{<figure src="./version_transfer.png#center" width=800px >}}

比如某种资源存在多个版本，比如 Foo 资源存在 v1、v2、v3 等三个版本，但其实在编码中，存在个内部版本 _internal ，该三个版本都是与内部版本互相转换，减少转换书写的复杂度.
Kubernetes 资源分为外部资源和内部资源。外部资源是对外可访问的，其版本为 v1/v1beta1 等，内部资源是 Kubernetes 内部访问的资源，其版本为 __internal.
```go
// /Users/python/go/pkg/mod/k8s.io/apimachinery@v0.24.3/pkg/runtime/interfaces.go
const (
	// APIVersionInternal may be used if you are registering a type that should not
	// be considered stable or serialized - it is a convention only and has no
	// special behavior in this package.
	APIVersionInternal = "__internal"
)
```
```go
// /Users/python/go/pkg/mod/k8s.io/apimachinery@v0.24.3/pkg/apis/meta/v1/register.go
func AddToGroupVersion(scheme *runtime.Scheme, groupVersion schema.GroupVersion) {
    // 资源的外部版本注册
	scheme.AddKnownTypeWithName(groupVersion.WithKind(WatchEventKind), &WatchEvent{})
	// 资源内部版本注册
	scheme.AddKnownTypeWithName(
		schema.GroupVersion{Group: groupVersion.Group, Version: runtime.APIVersionInternal}.WithKind(WatchEventKind),
		&InternalEvent{},
	)
}
```


```shell
# 描述资源版本信息
GET /api/{version}/{resource}/{action}
```

```shell
$ kubectl api-resources| head -1;kubectl api-resources |grep hpa
NAME                               SHORTNAMES           APIVERSION                              NAMESPACED   KIND
horizontalpodautoscalers           hpa                  autoscaling/v2                          true         HorizontalPodAutoscaler
$ kubectl get --raw /apis/autoscaling/v2/namespaces/istio-system/horizontalpodautoscalers/istio-ingressgateway-1-18-1 |jq .
```




## 案例

```go
package main

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func main() {
	// KnownType external
	coreGV := schema.GroupVersion{Group: "", Version: "v1"}
	extensionsGV := schema.GroupVersion{Group: "extensions", Version: "v1beta1"}

	// KnownType internal
	coreInternalGV := schema.GroupVersion{Group: "", Version: runtime.APIVersionInternal}

	// UnversionedType
	Unversioned := schema.GroupVersion{Group: "", Version: "v1"}

	schema := runtime.NewScheme()
	schema.AddKnownTypes(coreGV, &corev1.Pod{})
	schema.AddKnownTypes(extensionsGV, &appsv1.DaemonSet{})
	schema.AddKnownTypes(coreInternalGV, &corev1.Pod{})
	schema.AddUnversionedTypes(Unversioned, &metav1.Status{})

	fmt.Println(*schema)
    fmt.Println(schema.KnownTypes(coreGV))
}

```



## 数据结构 

```go
// k8s.io/apimachinery@v0.24.3/pkg/runtime/scheme.go
type Scheme struct {
	// 维护 GVK 和 model 对象类型的关系
	gvkToType map[schema.GroupVersionKind]reflect.Type

	// 维护 model 对象类型和 GVK 的关系.
	typeToGVK map[reflect.Type][]schema.GroupVersionKind

    // 无版本资源类型和 schema.GroupVersionKind 的映射
	unversionedTypes map[reflect.Type]schema.GroupVersionKind
	
	// 资源种类 Kind 和无版本资源类型的映射关系
	unversionedKinds map[string]reflect.Type

	// 维护 GVK label 标签转换函数的关系.
	fieldLabelConversionFuncs map[schema.GroupVersionKind]FieldLabelConversionFunc

	//  model 对象类型和默认值函数的关系
	defaulterFuncs map[reflect.Type]func(interface{})

	// 实现资源不同版本的转化.
	converter *conversion.Converter

	// versionPriority is a map of groups to ordered lists of versions for those groups indicating the
	// default priorities of these versions as registered in the scheme
	versionPriority map[string][]string

	// observedVersions keeps track of the order we've seen versions during type registration
	observedVersions []schema.GroupVersion

	// 定义 schema 的名称
	schemeName string
}
```

## AddKnownTypeWithName 注册资源：建立资源 Group/Version/Kind 和 model资源类型的相互映射关系
```go
func AddToGroupVersion(scheme *runtime.Scheme, groupVersion schema.GroupVersion) {
    scheme.AddKnownTypeWithName(groupVersion.WithKind(WatchEventKind), &WatchEvent{})
	//... 
}
```

```go
func (s *Scheme) AddKnownTypeWithName(gvk schema.GroupVersionKind, obj Object) {
	// ...
	t := reflect.TypeOf(obj)
    // ...
	t = t.Elem()
    // ...
	s.gvkToType[gvk] = t

	for _, existingGvk := range s.typeToGVK[t] {
		if existingGvk == gvk {
			return
		}
	}
	s.typeToGVK[t] = append(s.typeToGVK[t], gvk)
}	
```


## 内外部版本介绍--deployment

```go
// https://github.com/kubernetes/kubernetes/blob/8fbfbd96532598caf0faa294b3dcea7a22c4b0aa/staging/src/k8s.io/api/apps/v1/types.go
// 外部版本引用
type Deployment struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Specification of the desired behavior of the Deployment.
	// +optional
	Spec DeploymentSpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`

	// Most recently observed status of the Deployment.
	// +optional
	Status DeploymentStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

```
资源声明了 json 和 protobuf tag，以便于外部访问的序列化，反序列化操作。
API对象在不同的模块之间传输(尤其是跨进程)可能会用到序列化与反序列化，不同的场景对于序列化个格式又不同，比如grpc协议用protobuf，用户交互用yaml(因为yaml可读性强)，etcd存储用json



```go
// 内部版本引用
// https://github.com/kubernetes/kubernetes/blob/1d6df8233cb320d763293c420aff9d1f82d839dd/pkg/apis/apps/types.go
type Deployment struct {
	metav1.TypeMeta
	// +optional
	metav1.ObjectMeta

	// Specification of the desired behavior of the Deployment.
	// +optional
	Spec DeploymentSpec

	// Most recently observed status of the Deployment.
	// +optional
	Status DeploymentStatus
}
```


## 资源 convert

资源组下的每个外部资源版本都有 zz_generated.conversion.go 文件，该文件由 conversion-go 自动生成，文件中定义了外部资源到内部资源的相互转换。
```shell
# kubernetes/pkg/apis/apps/
apps/
    /v1
        /zz_generated.conversion.go
    /v1beta1
        /zz_generated.conversion.go
    /v1beta2
        /zz_generated.conversion.go

```


```go
// https://github.com/kubernetes/kubernetes/blob/af58b491ef15830c45039d76c552d1bc772df6bd/pkg/apis/apps/v1/zz_generated.conversion.go
func init() {
	localSchemeBuilder.Register(RegisterConversions)
}

// RegisterConversions adds conversion functions to the given scheme.
// Public to allow building arbitrary schemes.
func RegisterConversions(s *runtime.Scheme) error {
	// v1/DeploymentSpec 到 __internal/DeploymentSpec
	if err := s.AddGeneratedConversionFunc((*v1.DeploymentSpec)(nil), (*apps.DeploymentSpec)(nil), func(a, b interface{}, scope conversion.Scope) error {
	    return Convert_v1_DeploymentSpec_To_apps_DeploymentSpec(a.(*v1.DeploymentSpec), b.(*apps.DeploymentSpec), scope)
	}); err != nil {
	    return err
	}
    // __internal/DeploymentSpec 到 v1/DeploymentSpec
    if err := s.AddConversionFunc((*apps.DeploymentSpec)(nil), (*v1.DeploymentSpec)(nil), func(a, b interface{}, scope conversion.Scope) error {
        return Convert_apps_DeploymentSpec_To_v1_DeploymentSpec(a.(*apps.DeploymentSpec), b.(*v1.DeploymentSpec), scope)
    }); err != nil {
        return err
    }
}
```

```go
func (s *Scheme) AddGeneratedConversionFunc(a, b interface{}, fn conversion.ConversionFunc) error {
	return s.converter.RegisterGeneratedUntypedConversionFunc(a, b, fn)
}

```

## kube-apiserver 使用 scheme
```go
// CreateServerChain creates the apiservers connected via delegation.
func CreateServerChain(completedOptions completedServerRunOptions) (*aggregatorapiserver.APIAggregator, error) {
    // ... 
	// API 扩展服务（APIExtensionServer）
	apiExtensionsServer, err := createAPIExtensionsServer(apiExtensionsConfig, genericapiserver.NewEmptyDelegateWithCustomHandler(notFoundHandler))
	if err != nil {
		return nil, err
	}
    // API 核心服务（KubeAPIServer）
	kubeAPIServer, err := CreateKubeAPIServer(kubeAPIServerConfig, apiExtensionsServer.GenericAPIServer)
	if err != nil {
		return nil, err
	}

    // ...
	// API 聚合服务（AggregatorServer）
	aggregatorServer, err := createAggregatorServer(aggregatorConfig, kubeAPIServer.GenericAPIServer, apiExtensionsServer.Informers, crdAPIEnabled)
	if err != nil {
		// we don't need special handling for innerStopCh because the aggregator server doesn't create any go routines
		return nil, err
	}

	return aggregatorServer, nil
}
```

以 API 扩展服务（APIExtensionServer） 为例




实际是调用 scheme.ObjectKinds 方法获取对象类型
```go
// https://github.com/kubernetes/kubernetes/blob/78cb3862f11225135afdf76f3424e2d7b33104c7/staging/src/k8s.io/apimachinery/pkg/runtime/scheme.go
func (s *Scheme) ObjectKinds(obj Object) ([]schema.GroupVersionKind, bool, error) {
	// Unstructured objects are always considered to have their declared GVK
	if _, ok := obj.(Unstructured); ok {
		// we require that the GVK be populated in order to recognize the object
		gvk := obj.GetObjectKind().GroupVersionKind()
		if len(gvk.Kind) == 0 {
			return nil, false, NewMissingKindErr("unstructured object has no kind")
		}
		if len(gvk.Version) == 0 {
			return nil, false, NewMissingVersionErr("unstructured object has no version")
		}
		return []schema.GroupVersionKind{gvk}, false, nil
	}

	v, err := conversion.EnforcePtr(obj)
	if err != nil {
		return nil, false, err
	}
	t := v.Type()

	gvks, ok := s.typeToGVK[t]
	if !ok {
		return nil, false, NewNotRegisteredErrForType(s.schemeName, t)
	}
	_, unversionedType := s.unversionedTypes[t]

	return gvks, unversionedType, nil
}
```

示例代码
```go
package main

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kubernetes/pkg/apis/core"
)

func main() {
	pod := &core.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind: "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"name": "foo"},
		},
	}

	coreGV := schema.GroupVersion{Group: "", Version: "v1"}
	schema := runtime.NewScheme()
	schema.AddKnownTypes(coreGV, &core.Pod{})

	gvk, _, err := schema.ObjectKinds(pod)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(gvk)
}

```


## 参考

- [Kubernetes:kube-apiserver 之 scheme(一)](https://www.cnblogs.com/xingzheanan/p/17771090.html)

