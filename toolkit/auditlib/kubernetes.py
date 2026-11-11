"""Inventário K8s sem Secret/ConfigMap, exec ou alteração de contexto."""

RESOURCES = ("namespaces", "nodes", "pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs",
             "services", "ingresses", "networkpolicies", "roles", "rolebindings", "clusterroles", "clusterrolebindings",
             "serviceaccounts", "validatingwebhookconfigurations", "mutatingwebhookconfigurations",
             "validatingadmissionpolicies", "validatingadmissionpolicybindings", "persistentvolumes", "persistentvolumeclaims",
             "storageclasses", "resourcequotas", "limitranges")


def collect_context(runner, store, context, namespace=None, account=None, region=None):
    for resource in RESOURCES:
        print(f"[{context}] {resource}", flush=True)
        result = runner.kubernetes(context, resource, namespace)
        store.record("kubernetes", "kubernetes." + resource, region, account, context, result)
