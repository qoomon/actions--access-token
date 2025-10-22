# Actions--Access-Token Helm Chart
![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square)

This is a Helm chart for deploying Github Actions Access Token Server on Kubernetes. Make sure to build/push the [docker image first](server/Dockerfile)

## Install. Set Github AppID/Key and docker image registry path in `values.yaml`

```bash
helm install github-access-token-server . -f values.yaml
```

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity rules for pod assignment |
| autoscaling | object | `{"enabled":false,"maxReplicas":5,"minReplicas":1,"targetCPUUtilizationPercentage":80,"targetMemoryUtilizationPercentage":80}` | Horizontal Pod Autoscaler configuration |
| autoscaling.enabled | bool | `false` | Enable autoscaling |
| autoscaling.maxReplicas | int | `5` | Maximum number of replicas |
| autoscaling.minReplicas | int | `1` | Minimum number of replicas |
| autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage |
| autoscaling.targetMemoryUtilizationPercentage | int | `80` | Target memory utilization percentage |
| extraEnv | list | `[{"name":"LOG_LEVEL","value":"info"}]` | Additional environment variables to set in the container |
| extraObjects | list | `[]` | Extra Kubernetes objects to deploy (e.g., ConfigMaps, Secrets) |
| fullnameOverride | string | `""` | Override the full name of the release |
| githubAppId | string | `""` | GitHub App ID for authentication |
| githubAppPrivateKey | string | `""` | GitHub App private key in PEM format |
| httpRoute | object | `{"annotations":{},"enabled":false,"hostnames":["chart-example.local"],"parentRefs":[{"name":"gateway","sectionName":"http"}],"rules":[{"matches":[{"path":{"type":"PathPrefix","value":"/headers"}}]}]}` | Gateway API HTTPRoute configuration. Requires Gateway API resources and suitable controller installed within the cluster (see: https://gateway-api.sigs.k8s.io/guides/) |
| httpRoute.annotations | object | `{}` | HTTPRoute annotations |
| httpRoute.enabled | bool | `false` | Enable HTTPRoute |
| httpRoute.hostnames | list | `["chart-example.local"]` | Hostnames matching HTTP header |
| httpRoute.parentRefs | list | `[{"name":"gateway","sectionName":"http"}]` | Which Gateways this Route is attached to |
| httpRoute.rules | list | `[{"matches":[{"path":{"type":"PathPrefix","value":"/headers"}}]}]` | List of rules and filters applied |
| image | object | `{"pullPolicy":"IfNotPresent","repository":"","tag":""}` | Container image configuration |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| image.repository | string | `""` | Container image repository |
| image.tag | string | `""` | Overrides the image tag whose default is the chart appVersion |
| imagePullSecrets | list | `[]` | Secrets for pulling images from a private repository |
| ingress | object | `{"annotations":{},"className":"","enabled":true,"hosts":[{"host":"example.com","paths":[{"path":"/","pathType":"ImplementationSpecific"}]}],"tls":[]}` | Ingress configuration |
| ingress.annotations | object | `{}` | Ingress annotations |
| ingress.className | string | `""` | Ingress class name |
| ingress.enabled | bool | `true` | Enable ingress |
| ingress.hosts | list | `[{"host":"example.com","paths":[{"path":"/","pathType":"ImplementationSpecific"}]}]` | Ingress hosts configuration |
| ingress.tls | list | `[]` | Ingress TLS configuration |
| livenessProbe | object | `{}` | Liveness probe configuration |
| nameOverride | string | `""` | Override the chart name |
| nodeSelector | object | `{}` | Node selector for pod assignment |
| podAnnotations | object | `{}` | Annotations to add to the pod |
| podLabels | object | `{}` | Labels to add to the pod |
| podSecurityContext | object | `{}` | Pod security context configuration |
| readinessProbe | object | `{}` | Readiness probe configuration |
| replicaCount | int | `1` | Number of replicas for the deployment |
| resources | object | `{"limits":{"cpu":"100m","memory":"256Mi"},"requests":{"cpu":"100m","memory":"256Mi"}}` | Resource limits and requests for the container |
| securityContext | object | `{}` | Container security context configuration |
| service | object | `{"port":3000,"type":"ClusterIP"}` | Service configuration |
| service.port | int | `3000` | Service port |
| service.type | string | `"ClusterIP"` | Service type |
| serviceAccount | object | `{"annotations":{},"automount":true,"create":true,"name":""}` | Service account configuration |
| serviceAccount.annotations | object | `{}` | Annotations to add to the service account |
| serviceAccount.automount | bool | `true` | Automatically mount a ServiceAccount's API credentials |
| serviceAccount.create | bool | `true` | Specifies whether a service account should be created |
| serviceAccount.name | string | `""` | The name of the service account to use. If not set and create is true, a name is generated using the fullname template |
| tolerations | list | `[]` | Tolerations for pod assignment |
| volumeMounts | list | `[]` | Additional volumeMounts on the output Deployment definition |
| volumes | list | `[]` | Additional volumes on the output Deployment definition |

Autogenerated from chart metadata using [helm-docs](https://github.com/norwoodj/helm-docs)