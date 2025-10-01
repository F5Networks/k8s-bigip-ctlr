import yaml
import os
import ruamel.yaml

class MyDumper(yaml.Dumper):

    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, False)

cls_templt = """{{- if and .Values.rbac.create (not .Values.rbac.namespaced) -}}
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: {{ template "f5-bigip-ctlr.fullname" . }}
  labels:
    app.kubernetes.io/instance: {{ .Release.Name }}
    app.kubernetes.io/managed-by: {{ .Release.Service }}
    app.kubernetes.io/name: {{ template "f5-bigip-ctlr.name" . }}
    app: {{ template "f5-bigip-ctlr.name" . }}
    chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
    release: {{ .Release.Name }}
    heritage: {{ .Release.Service }} \n"""


ipam_rule_groups = ["apiextensions.k8s.io","fic.f5.com"]
non_ipam_rules=[]
ipam_rules=[]

root =  os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
rbac_dir = root+"/docs/config_examples/rbac/"
helm_clrole_path = root+"/helm-charts/f5-bigip-ctlr/templates/f5-bigip-ctlr-clusterrole.yaml"

with open(rbac_dir+'clusterrole.yaml',"r") as f:
   resources =  list(yaml.load_all(f,yaml.FullLoader))

for res in resources:
   if "rules" in res.keys():
      for rule in res["rules"]:
            if not list(set(ipam_rule_groups)&set(rule["apiGroups"])):
               non_ipam_rules.append(rule)
            else:
               ipam_rules.append(rule)


with open(helm_clrole_path,"w") as file_data:
   file_data.write(cls_templt)
   yaml = ruamel.yaml.YAML()
   yaml.indent(sequence=4, offset=2)
   yaml.dump({"rules":non_ipam_rules}, file_data)

   if ipam_rules:
      file_data.write("{{- if .Values.args.ipam }} \n")
      yaml.dump(ipam_rules, file_data)
      file_data.write("{{- end }}\n")
      file_data.write("{{- end }}\n")