#! /bin/bash



readonly SSL_COUNTRY="Czech Republic"
readonly SSL_STATE="CZ"
readonly SSL_LOCATION="Prague"
readonly SSL_ORG="Example"
readonly SSL_OU="Development"
readonly SSL_EMAIL="dev@example.com"
readonly DEFAULT_DOWNLOAD_PATH="/tmp/helm/helm.tar.gz"
readonly DEFAULT_HELM_TAR_PKG_NAME="helm.tar.gz"
readonly DEFAULT_TILLER_PROJECT="helm-tiller"
readonly DEFAULT_HELM_VERSION="2.13.1"
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly APPS_NEEDED="oc aws"
readonly DEFAULT_PROJECTS_WHITELIST="staging,utility"
readonly ACM_PCA_ARN=''
readonly AWS_CLI_PROFILE='dev'
readonly AWS_REGION='us-east-1'
readonly TILLER_YAML=$(cat <<EOF | base64 -d
LS0tCmtpbmQ6IFRlbXBsYXRlCmFwaVZlcnNpb246IHYxCm9iamVjdHM6Ci0ga2luZDogU2Vydmlj
ZUFjY291bnQKICBhcGlWZXJzaW9uOiB2MQogIG1ldGFkYXRhOgogICAgbmFtZTogdGlsbGVyCgot
IGtpbmQ6IFJvbGUKICBhcGlWZXJzaW9uOiB2MQogIG1ldGFkYXRhOgogICAgbmFtZTogdGlsbGVy
CiAgcnVsZXM6CiAgLSBhcGlHcm91cHM6CiAgICAtICIiCiAgICByZXNvdXJjZXM6CiAgICAtIGNv
bmZpZ21hcHMKICAgIHZlcmJzOgogICAgLSBjcmVhdGUKICAgIC0gZ2V0CiAgICAtIGxpc3QKICAg
IC0gdXBkYXRlCiAgICAtIGRlbGV0ZQogIC0gYXBpR3JvdXBzOgogICAgLSAiIgogICAgcmVzb3Vy
Y2VzOgogICAgLSBuYW1lc3BhY2VzCiAgICB2ZXJiczoKICAgIC0gZ2V0CgotIGtpbmQ6IFJvbGVC
aW5kaW5nCiAgYXBpVmVyc2lvbjogdjEKICBtZXRhZGF0YToKICAgIG5hbWU6IHRpbGxlcgogIHJv
bGVSZWY6CiAgICBuYW1lOiB0aWxsZXIKICAgIG5hbWVzcGFjZTogJHtUSUxMRVJfTkFNRVNQQUNF
fQogIHN1YmplY3RzOgogIC0ga2luZDogU2VydmljZUFjY291bnQKICAgIG5hbWU6IHRpbGxlcgoK
LSBhcGlWZXJzaW9uOiBleHRlbnNpb25zL3YxYmV0YTEKICBraW5kOiBEZXBsb3ltZW50CiAgbWV0
YWRhdGE6CiAgICBsYWJlbHM6CiAgICAgIGFwcDogaGVsbQogICAgICBuYW1lOiB0aWxsZXIKICAg
IG5hbWU6IHRpbGxlcgogIHNwZWM6CiAgICByZXBsaWNhczogMQogICAgc2VsZWN0b3I6CiAgICAg
IG1hdGNoTGFiZWxzOgogICAgICAgIGFwcDogaGVsbQogICAgICAgIG5hbWU6IHRpbGxlcgogICAg
dGVtcGxhdGU6CiAgICAgIG1ldGFkYXRhOgogICAgICAgIGxhYmVsczoKICAgICAgICAgIGFwcDog
aGVsbQogICAgICAgICAgbmFtZTogdGlsbGVyCiAgICAgIHNwZWM6CiAgICAgICAgY29udGFpbmVy
czoKICAgICAgICAtIG5hbWU6IHRpbGxlcgogICAgICAgICAgaW1hZ2U6IGdjci5pby9rdWJlcm5l
dGVzLWhlbG0vdGlsbGVyOiR7SEVMTV9WRVJTSU9OfQogICAgICAgICAgZW52OgogICAgICAgICAg
LSBuYW1lOiBUSUxMRVJfTkFNRVNQQUNFCiAgICAgICAgICAgIHZhbHVlRnJvbToKICAgICAgICAg
ICAgICBmaWVsZFJlZjoKICAgICAgICAgICAgICAgIGZpZWxkUGF0aDogbWV0YWRhdGEubmFtZXNw
YWNlCiAgICAgICAgICAtIG5hbWU6IFRJTExFUl9ISVNUT1JZX01BWAogICAgICAgICAgICB2YWx1
ZTogIjUwIgogICAgICAgICAgcG9ydHM6CiAgICAgICAgICAtIG5hbWU6IHRpbGxlcgogICAgICAg
ICAgICBjb250YWluZXJQb3J0OiA0NDEzNAogICAgICAgICAgcmVhZGluZXNzUHJvYmU6CiAgICAg
ICAgICAgIGh0dHBHZXQ6CiAgICAgICAgICAgICAgcGF0aDogL3JlYWRpbmVzcwogICAgICAgICAg
ICAgIHBvcnQ6IDQ0MTM1CiAgICAgICAgICBsaXZlbmVzc1Byb2JlOgogICAgICAgICAgICBodHRw
R2V0OgogICAgICAgICAgICAgIHBhdGg6IC9saXZlbmVzcwogICAgICAgICAgICAgIHBvcnQ6IDQ0
MTM1CiAgICAgICAgc2VydmljZUFjY291bnROYW1lOiB0aWxsZXIKCnBhcmFtZXRlcnM6Ci0gbmFt
ZTogSEVMTV9WRVJTSU9OCiAgdmFsdWU6IHYyLjYuMQogIHJlcXVpcmVkOiB0cnVlCi0gbmFtZTog
VElMTEVSX05BTUVTUEFDRQogIHJlcXVpcmVkOiB0cnVlCi4uLgo=
EOF
)
readonly TILLER_YAML_TLS=$(cat <<EOF | base64 -d
LS0tCmtpbmQ6IFRlbXBsYXRlCmFwaVZlcnNpb246IHYxCm9iamVjdHM6Ci0ga2luZDogU2Vydmlj
ZUFjY291bnQKICBhcGlWZXJzaW9uOiB2MQogIG1ldGFkYXRhOgogICAgbmFtZTogdGlsbGVyCgot
IGtpbmQ6IFJvbGUKICBhcGlWZXJzaW9uOiB2MQogIG1ldGFkYXRhOgogICAgbmFtZTogdGlsbGVy
CiAgcnVsZXM6CiAgLSBhcGlHcm91cHM6CiAgICAtICIiCiAgICByZXNvdXJjZXM6CiAgICAtIGNv
bmZpZ21hcHMKICAgIHZlcmJzOgogICAgLSBjcmVhdGUKICAgIC0gZ2V0CiAgICAtIGxpc3QKICAg
IC0gdXBkYXRlCiAgICAtIGRlbGV0ZQogIC0gYXBpR3JvdXBzOgogICAgLSAiIgogICAgcmVzb3Vy
Y2VzOgogICAgLSBuYW1lc3BhY2VzCiAgICB2ZXJiczoKICAgIC0gZ2V0CgotIGtpbmQ6IFJvbGVC
aW5kaW5nCiAgYXBpVmVyc2lvbjogdjEKICBtZXRhZGF0YToKICAgIG5hbWU6IHRpbGxlcgogIHJv
bGVSZWY6CiAgICBuYW1lOiB0aWxsZXIKICAgIG5hbWVzcGFjZTogJHtUSUxMRVJfTkFNRVNQQUNF
fQogIHN1YmplY3RzOgogIC0ga2luZDogU2VydmljZUFjY291bnQKICAgIG5hbWU6IHRpbGxlcgoK
LSBhcGlWZXJzaW9uOiBleHRlbnNpb25zL3YxYmV0YTEKICBraW5kOiBEZXBsb3ltZW50CiAgbWV0
YWRhdGE6CiAgICBsYWJlbHM6CiAgICAgIGFwcDogaGVsbQogICAgICBuYW1lOiB0aWxsZXIKICAg
IG5hbWU6IHRpbGxlcgogIHNwZWM6CiAgICByZXBsaWNhczogMQogICAgc2VsZWN0b3I6CiAgICAg
IG1hdGNoTGFiZWxzOgogICAgICAgIGFwcDogaGVsbQogICAgICAgIG5hbWU6IHRpbGxlcgogICAg
dGVtcGxhdGU6CiAgICAgIG1ldGFkYXRhOgogICAgICAgIGxhYmVsczoKICAgICAgICAgIGFwcDog
aGVsbQogICAgICAgICAgbmFtZTogdGlsbGVyCiAgICAgIHNwZWM6CiAgICAgICAgY29udGFpbmVy
czoKICAgICAgICAtIG5hbWU6IHRpbGxlcgogICAgICAgICAgaW1hZ2U6IGdjci5pby9rdWJlcm5l
dGVzLWhlbG0vdGlsbGVyOiR7SEVMTV9WRVJTSU9OfQogICAgICAgICAgZW52OgogICAgICAgICAg
LSBuYW1lOiBUSUxMRVJfTkFNRVNQQUNFCiAgICAgICAgICAgIHZhbHVlRnJvbToKICAgICAgICAg
ICAgICBmaWVsZFJlZjoKICAgICAgICAgICAgICAgIGZpZWxkUGF0aDogbWV0YWRhdGEubmFtZXNw
YWNlCiAgICAgICAgICAtIG5hbWU6IFRJTExFUl9ISVNUT1JZX01BWAogICAgICAgICAgICB2YWx1
ZTogIjUwIgogICAgICAgICAgLSBuYW1lOiBUSUxMRVJfVExTX1ZFUklGWQogICAgICAgICAgICB2
YWx1ZTogIjEiCiAgICAgICAgICAtIG5hbWU6IFRJTExFUl9UTFNfRU5BQkxFCiAgICAgICAgICAg
IHZhbHVlOiAiMSIKICAgICAgICAgIC0gbmFtZTogVElMTEVSX1RMU19DRVJUUwogICAgICAgICAg
ICB2YWx1ZTogL2V0Yy9jZXJ0cwogICAgICAgICAgcG9ydHM6CiAgICAgICAgICAtIGNvbnRhaW5l
clBvcnQ6IDQ0MTM0CiAgICAgICAgICAgIG5hbWU6IHRpbGxlcgogICAgICAgICAgLSBjb250YWlu
ZXJQb3J0OiA0NDEzNQogICAgICAgICAgICBuYW1lOiBodHRwCiAgICAgICAgICByZWFkaW5lc3NQ
cm9iZToKICAgICAgICAgICAgaHR0cEdldDoKICAgICAgICAgICAgICBwYXRoOiAvcmVhZGluZXNz
CiAgICAgICAgICAgICAgcG9ydDogNDQxMzUKICAgICAgICAgIGxpdmVuZXNzUHJvYmU6CiAgICAg
ICAgICAgIGh0dHBHZXQ6CiAgICAgICAgICAgICAgcGF0aDogL2xpdmVuZXNzCiAgICAgICAgICAg
ICAgcG9ydDogNDQxMzUKICAgICAgICAgIHZvbHVtZU1vdW50czoKICAgICAgICAgIC0gbW91bnRQ
YXRoOiAvZXRjL2NlcnRzCiAgICAgICAgICAgIG5hbWU6IHRpbGxlci1jZXJ0cwogICAgICAgICAg
ICByZWFkT25seTogdHJ1ZQogICAgICAgIHNlcnZpY2VBY2NvdW50TmFtZTogdGlsbGVyCiAgICAg
ICAgdm9sdW1lczoKICAgICAgICAtIG5hbWU6IHRpbGxlci1jZXJ0cwogICAgICAgICAgc2VjcmV0
OgogICAgICAgICAgICBzZWNyZXROYW1lOiB0aWxsZXItc2VjcmV0CgpwYXJhbWV0ZXJzOgotIG5h
bWU6IEhFTE1fVkVSU0lPTgogIHZhbHVlOiB2Mi42LjEKICByZXF1aXJlZDogdHJ1ZQotIG5hbWU6
IFRJTExFUl9OQU1FU1BBQ0UKICByZXF1aXJlZDogdHJ1ZQouLi4K
EOF
)

function print_usage {
  echo
  echo "Usage: deploy_helm_tiller.sh [OPTIONS]"
  echo
  echo "This script is intended to deploy Helm Tiller server to the Openshift platform."
  echo
  echo "Options:"
  echo
  echo -e "  --ocp-api-url\t\tAPI of the OpenShift cluster to use. Needed if \"--no-login\" not specified."
  echo -e "  --no-login\t\tBypass the Openshift login. This assumes that you are already logged in to the right cluster."
  echo -e "  --tiller-project\tOpenShift project in which the Tiller will be deployed. Defaults to helm-tiller."
  echo -e "  --helm-version\tSpecify Helm version to deploy. Defaults to \"2.13.1\"."
  echo -e "  --project-whitelist\tProjects where tiller should have access to. Defaults to \"staging,utility\"."
  echo -e "                     \tPlease, see examples bellow for more information."
  echo -e "  --tls\t\t\tThis option will generate TLS certificates for the tiller server and create proper secrets."
  echo -e "  --help\t\tShows this help."
  echo
  echo "Example:"
  echo
  echo "  Deploy with the default settings:"
  echo "  $SCRIPT_NAME --ocp-api-url https://openshift.example.com:8443"
  echo
  echo "  Whitelist \"my-project\" and \"another-project\" projects:"
  echo "  $SCRIPT_NAME --project-whitelist \"my-project,another-project\" --ocp-api-url https://openshift.example.com:8443"
  echo
}

function log {
  local -r level="$1"
  local -r message="$2"
  local -r timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  >&2 echo -e "${timestamp} [${level}] [$SCRIPT_NAME] ${message}"
}

function log_info {
  local -r message="$1"
  log "INFO" "\e[0;32m$message\e[0m"
}

function log_warn {
  local -r message="$1"
  log "WARN" "\e[0;33m$message\e[0m"
}

function log_error {
  local -r message="$1"
  log "ERROR" "\e[0;31m$message\e[0m"
}

function assert_not_empty {
  local -r arg_name="$1"
  local -r arg_value="$2"

  if [[ -z "$arg_value" ]]; then
    log_error "The value for '$arg_name' cannot be empty"
    print_usage
    exit 1
  fi
}

function retry {
  local -r cmd="$1"
  local -r description="$2"
  log_info "$cmd"
  for i in $(seq 1 5); do
    log_info "$description"

    # The boolean operations with the exit status are there to temporarily circumvent the "set -e" at the
    # beginning of this script which exits the script immediatelly for error status while not losing the exit status code
    output=$(eval "$cmd") && exit_status=0 || exit_status=$?
    log_info "$output"
    if [[ $exit_status -eq 0 ]]; then
      echo "$output"
      return
    fi
    log_warn "$description failed. Will sleep for 10 seconds and try again."
    sleep 10
  done;

  log_error "$description failed after 5 attempts."
  exit $exit_status
}

function check_dependencies {
  local -r dependency="$1"
  
  if ! command -v $dependency >/dev/null; then
    log_error "Command \"$dependency\" not found!"
    return 1
  fi
}

function want_continue {
  local response="N"

  while read -p "Do you want to continue? [N/y]" -r response
  do
    if [ "x$response" == "x" ]; then
      log_info "Aborting..."
      exit 0 
    elif [ "$(echo $response | tr '[:upper:]' '[:lower:]')" == "y" ]; then
      log_info "Continuing..."
      return
    elif [ "$(echo $response | tr '[:upper:]' '[:lower:]')" == "n" ]; then
      log_info "Aborting..."
      exit 0
    else
      echo "Please, choose y or n !!!"
    fi
  done
}

function openshift_login {
    local -r ocp_api_url="$1"
    oc login $ocp_api_url
}

function openshift_tiller_project {
  local -r tiller_project="$1"
  (oc project $tiller_project 2>&1) >/dev/null
  if [ "$?" -eq "0" ]; then
    log_warn "Project $1 already exists!"
    want_continue
  else
    oc new-project $tiller_project >/dev/null
    oc project $tiller_project >/dev/null
    log_info "Using project $tiller_project"
  fi
}

function install_helm_client {
  local -r helm_version="$1"
  local -r binary_name="helm"
  local -r os_type="$(uname -s | tr '[:upper:]' '[:lower:]')"
  local -r download_url="https://storage.googleapis.com/kubernetes-helm/helm-v${helm_version}-${os_type}-amd64.tar.gz"

  check_dependencies "$binary_name"
  [ "$?" -eq 0 ] && return || log_info "Helm binary is not present"

  log_info "Creating a directory for download"
  mkdir -p $DEFAULT_DOWNLOAD_PATH
  retry \
    "curl -o '$DEFAULT_DOWNLOAD_PATH/$DEFAULT_HELM_TAR_PKG_NAME' '$download_url' --location --silent --fail --show-error" \
    "Downloading helm client package to $DEFAULT_DOWNLOAD_PATH"
  
  log_info "Extracting the tar package"
  tar xzf $DEFAULT_DOWNLOAD_PATH/$DEFAULT_HELM_TAR_PKG_NAME -C $DEFAULT_DOWNLOAD_PATH
  
  if [ $(id -u) -eq 0 ]; then
    log_info "Moving helm binary to \"/usr/bin/\" directory"
    local target_path="/usr/bin/"
  else
    log_info "Moving helm binary to \"$HOME/.local/bin/\" directory"
    local target_path="$HOME/.local/bin/"
  fi

  mv $DEFAULT_DOWNLOAD_PATH/$os_type-amd64/helm $target_path
  log_info "Initializing helm client"
  helm init --client-only >/dev/null
}

function ssl_certs {
  local openssl_conf=$(cat <<-EOF
    [req]
    prompt                  = no
    default_bits            = 2048
    default_md              = sha256
    distinguished_name      = dn
    req_extensions          = reqext
    
    [dn]
    C                       = $SSL_COUNTRY
    ST                      = $SSL_STATE
    L                       = $SSL_LOCATION
    O                       = $SSL_ORG
    OU                      = $SSL_OU
    emailAddress            = $SSL_EMAIL
    CN                      = tiller-server
    
    [reqext]
    nsComment               = "OpenSSL Generated Certificate"
    basicConstraints        = CA:FALSE
    nsCertType              = server
    keyUsage                = nonRepudiation,digitalSignature,keyEncipherment
    extendedKeyUsage        = serverAuth,clientAuth
    subjectKeyIdentifier    = hash
EOF
)
    local key_csr=$(openssl req -new -sha256 -nodes -newkey rsa:2048  -config <(echo "$openssl_conf") 2>/dev/null)

    local cert_arn=$(aws acm-pca issue-certificate \
                       --certificate-authority-arn "${ACM_PCA_ARN}" \
                       --csr file://<(echo "$key_csr" | awk '/BEGIN .* REQUEST/,/END .* REQUEST/') \
                       --signing-algorithm "SHA256WITHRSA" \
                       --validity Value=1095,Type="DAYS" \
                       --idempotency-token 8888 --profile "$AWS_CLI_PROFILE" \
                       --region "$AWS_REGION" \
                       --output text | awk '{print $NF}')

    local cert=$(aws acm-pca get-certificate \
                       --certificate-authority-arn "${ACM_PCA_ARN}" \
                       --certificate-arn ${cert_arn} --output text --query 'Certificate' \
                       --region "$AWS_REGION" \
                       --profile "$AWS_CLI_PROFILE" 2>/dev/null)

    local certchain=$(aws acm-pca get-certificate \
                       --certificate-authority-arn ${ACM_PCA_ARN} \
                       --certificate-arn ${cert_arn} --output text --query 'CertificateChain' \
                       --region "$AWS_REGION" \
                       --profile "$AWS_CLI_PROFILE" 2>/dev/null | \
                       sed -E 's/-{10}/-----\n-----/')

    jq -n "{
             \"key\": \"$(echo "$key_csr" | awk '/BEGIN PRIVATE KEY/,/END PRIVATE KEY/')\",
             \"cert\": \"$cert\",
             \"chain\": \"$certchain\"
           }"
}

function deploy_tiller {
  local -r helm_version="$1"
  local -r tiller_project="$2"
  local -r template_file="$3"
  local -r tls="$4"
  local oc_process_tls=""

  if [ "$tls" == "true" ]; then
    log_info "Preparing certificates"
    local -r certs="$(ssl_certs)"
    local -r ca_cert=$(echo $certs | jq -r '.chain')
    local -r cert=$(echo $certs | jq -r '.cert')
    local -r key=$(echo $certs | jq -r '.key')
    
    log_info "Creating secrets"
    oc create secret generic tiller-secret -n $tiller_project --from-literal=ca.crt="$ca_cert" --from-literal=tls.crt="$cert" --from-literal=tls.key="$key" >/dev/null
  fi
  log_info "Deploying tiller"
  echo "$template_file" | oc process -f - -p TILLER_NAMESPACE="$tiller_project" -p HELM_VERSION="v$helm_version" | \
    oc create -n $tiller_project -f - >/dev/null
  check_result "$?"
}

function delete_tiller {
  local -r helm_version="$1"
  local -r tiller_project="$2"
  local -r template_file="$3"
  local -r project_whitelist="$4"
  local -r tls="$5"
  local -r non_ocp_projects="$(oc get projects --no-headers=true | cut -d ' ' -f1 | grep -E "$project_whitelist")"
  local oc_process_tls=""
  local output


  log_info "Deleting tiller"
  oc project "$tiller_project" >/dev/null
  output=`(echo "$template_file" | oc process -f - -p TILLER_NAMESPACE="$tiller_project" -p HELM_VERSION="v$helm_version" | oc delete -f - >/dev/null) 2>&1`
  if [ -n "$output" ]; then
      log_warn "$output"
  fi

  if [ "$tls" == "true" ]; then
    log_info "Removing secrets"
    oc delete secret tiller-secret -n $tiller_project >/dev/null
  fi

  log_info "Removing permissions from whitelisted projects"
  for project in $non_ocp_projects; do
    log_info "Removing permissons from project $project"
    oc project $project >/dev/null
    output=`(oc policy remove-role-from-user admin "system:serviceaccount:${tiller_project}:tiller" >/dev/null) 2>&1`
    if [ -n "$output" ]; then
      log_warn "$output"
    fi
  done
}

function openshift_grant_permissions {
  local -r tiller_project="$1"
  local -r project_whitelist="$2"
  local -r non_ocp_projects="$(oc get projects --no-headers=true | cut -d ' ' -f1 | grep -E "$project_whitelist")"
  local output

  log_info "Setting up permissions for whitelisted projects"
  for project in $non_ocp_projects; do
    log_info "Setting permissons on project $project"
    oc project $project >/dev/null
    output=`(oc policy add-role-to-user admin "system:serviceaccount:${tiller_project}:tiller" >/dev/null) 2>&1`
    if [ -n "$output" ]; then
      log_warn "$output"
    fi
  done
}

function show_tiller_status {
  local tiller_project="$1"
  
  oc project $tiller_project >/dev/null
  log_info "Here is tiller deployment status: $(oc rollout status deployment tiller 2>&1)"
  check_result "$?"
}

function check_result {
  local -r result="$1"

  if [ "$result" -ne 0 ]; then
    log_error "Command exited with non-zero code!"
    exit 1
  fi
}

function deploy {
  if [[ $# == 0 ]]; then
    print_usage
    exit 0
  fi

  local ocp_api_url=""
  local tiller_project="$DEFAULT_TILLER_PROJECT"
  local helm_version="$DEFAULT_HELM_VERSION"
  local project_whitelist="$DEFAULT_PROJECTS_WHITELIST"
  local delete_tiller="false"
  local no_login="false"
  local tls="false"

  while [[ $# > 0 ]]; do
    local key="$1"

    case "$key" in
      --ocp-api-url)
        ocp_api_url="$2"
        shift
        ;;
      --tiller-project)
        tiller_project="$2"
        shift
        ;;
      --helm-version)
        helm_version="$2"
        shift
        ;;
      --project-whitelist)
        project_whitelist="$2"
        shift
        ;;
      --tls)
        tls="true"
        ;;
      --delete)
        delete_tiller="true"
        ;;
      --no-login)
        no_login="true"
        ;;
      --help)
        print_usage
        exit
        ;;
      *)
        log_error "Unrecognized argument: $key"
        print_usage
        exit 1
        ;;
    esac

    shift
  done
  
  if [ "$tls" == "true" ]; then
    local -r template_file="$TILLER_YAML_TLS"
  else
    local -r template_file="$TILLER_YAML"
  fi
  # Process whitelist to fit to 'grep -E'
  project_whitelist="$(echo $project_whitelist | sed 's/,/|/g')"

  log_info "Starting Helm Tiller deployment script"
  
  # Check if all needed apps are installed.
  local not_installed_apps=0
  for i in $APPS_NEEDED; do
    check_dependencies "$i"
    [ "$?" -eq "0" ] && log_info "App $i is installed" || (log_error "App $i is not installed" && let "$not_installed_apps++")
  done
  if ! [ "$not_installed_apps" -eq "0" ]; then
    log_error "There are $not_installed_apps apps not installed but needed. Please, install them first and make them available in \$PATH"
    exit 1
  fi

  local -r oc_version="$(oc version | head -n 1 | awk '{ print $2}' | sed 's/v3\.\(.\).*/\1/')"
  if [ "$oc_version" -lt "6" ]; then
    log_error "Unsupported \"oc\" version. Tiller works with Openshift v3.6 and greater"
    exit 1
  fi

  if [ "$no_login" == "false" ]; then
    assert_not_empty "--ocp-api-url" "$ocp_api_url"
    openshift_login "$ocp_api_url"
  fi
  if [ "$delete_tiller" == "true" ]; then
    delete_tiller "$helm_version" "$tiller_project" "$template_file" "$project_whitelist" "$tls"
    log_info "Tiller has been deleted"
    log_warn "Tiller project has been preserved, you have to delete it manually."
    exit 0
  fi
  openshift_tiller_project "$tiller_project"
  install_helm_client "$helm_version"
  deploy_tiller "$helm_version" "$tiller_project" "$template_file" "$tls"
  openshift_grant_permissions "$tiller_project" "$project_whitelist"
  show_tiller_status "$tiller_project"
  log_info "To use helm, please run the command \"export TILLER_NAMESPACE=$tiller_project\""
}

deploy "$@"
