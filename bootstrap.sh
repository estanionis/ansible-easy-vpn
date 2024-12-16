#!/bin/bash -uxe
exec > >(tee -i $HOME/ansible-easy-vpn/bootstrap.log) 2>&1
# A bash script that prepares the OS
# before running the Ansible playbook

# Discard stdin. Needed when running from an one-liner which includes a newline
#read -N 999999 -t 0.001

# Quit on error
set -e

# Detect OS
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
  if [[ "$os_version" -lt 2004 ]]; then
      echo "Ubuntu 20.04 or higher is required to use this installer."
      echo "This version of Ubuntu is too old and unsupported."
      exit
    fi
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
  if [[ "$os_version" -lt 11 ]]; then
      echo "Debian 11 or higher is required to use this installer."
      echo "This version of Debian is too old and unsupported."
      exit
  fi
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
  if [[ "$os_version" -lt 8 ]]; then
      echo "Rocky Linux 8 or higher is required to use this installer."
      echo "This version of Rocky/CentOS is too old and unsupported."
      exit
  fi
fi

check_root() {
# Check if the user is root or not
if [[ $EUID -ne 0 ]]; then
  if [[ ! -z "$1" ]]; then
    SUDO='sudo -E -H'
  else
    SUDO='sudo -E'
  fi
else
  SUDO=''
fi
}

install_dependencies_debian() {
  REQUIRED_PACKAGES=(
    sudo
    software-properties-common
    dnsutils
    curl
    git
    locales
    rsync
    apparmor
    python3
    python3-setuptools
    python3-apt
    python3-venv
    python3-pip
    aptitude
    direnv
    iptables
  )

  REQUIRED_PACKAGES_ARM64=(
    gcc
    python3-dev
    libffi-dev
    libssl-dev
    make
  )

  check_root
  # Disable interactive apt functionality
  export DEBIAN_FRONTEND=noninteractive
  # Update apt database, update all packages and install Ansible + dependencies
  $SUDO apt update -y;
  yes | $SUDO apt-get -o Dpkg::Options::="--force-confold" -fuy dist-upgrade;
  yes | $SUDO apt-get -o Dpkg::Options::="--force-confold" -fuy install "${REQUIRED_PACKAGES[@]}"
  yes | $SUDO apt-get -o Dpkg::Options::="--force-confold" -fuy autoremove;
  [ $(uname -m) == "aarch64" ] && yes | $SUDO apt install -fuy "${REQUIRED_PACKAGES_ARM64[@]}"
  export DEBIAN_FRONTEND=
}

install_dependencies_centos() {
  check_root
  REQUIRED_PACKAGES=(
    sudo
    bind-utils
    curl
    git
    rsync
    https://kojipkgs.fedoraproject.org//vol/fedora_koji_archive02/packages/direnv/2.12.2/1.fc28/x86_64/direnv-2.12.2-1.fc28.x86_64.rpm
  )
  if [[ "$os_version" -eq 9 ]]; then
    REQUIRED_PACKAGES+=(
      python3
      python3-setuptools
      python3-pip
      python3-firewall
    )
  else 
    REQUIRED_PACKAGES+=(
      python39
      python39-setuptools
      python39-pip
      python3-firewall
      # kmod-wireguard
      # https://ftp.gwdg.de/pub/linux/elrepo/elrepo/el8/x86_64/RPMS/kmod-wireguard-1.0.20220627-4.el8_7.elrepo.x86_64.rpm
    )
    $SUDO dnf install -y https://www.elrepo.org/elrepo-release-8.el8.elrepo.noarch.rpm
    $SUDO dnf install -y kmod-wireguard
  fi
  $SUDO dnf update -y
  $SUDO dnf install -y epel-release
  $SUDO dnf install -y "${REQUIRED_PACKAGES[@]}"
}

# Install all the dependencies
if [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
  install_dependencies_debian
elif [[ "$os" == "centos" ]]; then
  install_dependencies_centos
fi

# Clone the Ansible playbook
if [ -d "$HOME/ansible-easy-vpn" ]; then
  pushd $HOME/ansible-easy-vpn
  git pull
  popd
else
  git clone https://github.com/estanionis/ansible-easy-vpn $HOME/ansible-easy-vpn
fi

# Set up a Python venv
set +e
if which python3.9; then
  PYTHON=$(which python3.9)
else
  PYTHON=$(which python3)
fi
set -e
cd $HOME/ansible-easy-vpn
[ -d $HOME/ansible-easy-vpn/.venv ] || $PYTHON -m venv .venv
export VIRTUAL_ENV="$HOME/ansible-easy-vpn/.venv"
export PATH="$HOME/ansible-easy-vpn/.venv/bin:$PATH"
.venv/bin/python3 -m pip install --upgrade pip
.venv/bin/python3 -m pip install -r requirements.txt



# Install the Galaxy requirements
cd $HOME/ansible-easy-vpn && ansible-galaxy install --force -r requirements.yml

# Check if we're running on an AWS EC2 instance
set +e
aws=$(curl -m 5 -s http://169.254.169.254/latest/meta-data/ami-id)

if [[ "$aws" =~ ^ami.*$ ]]; then
  aws=true
else
  aws=false
fi
set -e

touch $HOME/ansible-easy-vpn/custom.yml

custom_filled=$(awk -v RS="" '/username/&&/dns_nameservers/&&/root_host/{print FILENAME}' $HOME/ansible-easy-vpn/custom.yml)

if [[ "$custom_filled" =~ "custom.yml" ]]; then
  clear
  echo "custom.yml already exists. Running the playbook..."
  echo
  echo "If you want to change something (e.g. username, domain name, etc.)"
  echo "Please edit custom.yml or secret.yml manually, and then re-run this script"
  echo
  cd $HOME/ansible-easy-vpn && ansible-playbook --ask-vault-pass run.yml
  exit 0
fi

clear
echo "Welcome to ansible-easy-vpn!"
echo
echo "This script is interactive"
echo "If you prefer to fill in the custom.yml file manually,"
echo "press [Ctrl+C] to quit this script"
echo
echo "Enter your desired UNIX username"
read -p "Username: " username
echo "Enter your desired UNIX username"
read -p "Username: " username
until [[ "$username" =~ ^[a-z0-9]{3,16}$ ]]; do
  echo "Invalid username: must be 3-16 characters, lowercase letters and numbers only."
  read -p "Username: " username
done

echo "username: \"${username}\"" >> $HOME/ansible-easy-vpn/custom.yml

echo
echo "Enter your user password"
echo "This password will be used for Authelia login, administrative access and SSH login"
read -s -p "Password: " user_password
until [[ "${#user_password}" -ge 8 && "${#user_password}" -lt 60 ]]; do
  echo
  echo "Invalid password: must be between 8 and 59 characters."
  read -s -p "Password: " user_password
done
echo
read -s -p "Repeat password: " user_password2
echo
until [[ "$user_password" == "$user_password2" ]]; do
  echo
  echo "The passwords don't match"
  read -s -p "Password: " user_password
  echo
  read -s -p "Repeat password: " user_password2
done

echo
echo "Would you like to enable Adguard, Unbound and DNS-over-HTTP"
echo "for secure DNS resolution with ad blocking functionality?"
echo "This functionality is experimental and might lead to instability"
echo
read -p "Enable Adguard? [y/N]: " adguard_enable
until [[ "$adguard_enable" =~ ^[yYnN]*$ ]]; do
  echo "$adguard_enable: invalid selection."
  read -p "[y/N]: " adguard_enable
done
if [[ "$adguard_enable" =~ ^[yY]$ ]]; then
  echo "enable_adguard_unbound_doh: true" >> $HOME/ansible-easy-vpn/custom.yml
fi

echo
echo
echo "Enter your domain name"
echo "The domain name should already resolve to the IP address of your server"
if [[ "$adguard_enable" =~ ^[yY]$ ]]; then
  echo "Make sure that 'wg', 'auth' and 'adguard' subdomains also point to that IP (not necessary with DuckDNS)"
else
  echo "Make sure that 'wg' and 'auth' subdomains also point to that IP (not necessary with DuckDNS)"
fi
echo
read -p "Domain name: " root_host
until [[ -n "$root_host" && "$root_host" =~ ^[a-z0-9\.\-]+$ ]]; do
  echo "Invalid domain name: only letters, numbers, dots, and hyphens are allowed."
  read -p "Domain name: " root_host
done

public_ip=$(curl -s https://api.ipify.org)
domain_ip=$(dig +short @1.1.1.1 ${root_host})

# Patikriname, ar DNS grąžina reikšmę
if [[ -z "$domain_ip" ]]; then
  echo "ERROR: Unable to resolve the domain $root_host. Check your DNS settings."
  exit 1
fi

# Tikriname, ar domeno IP sutampa su viešuoju serverio IP
until [[ $domain_ip =~ $public_ip ]]; do
  echo
  echo "The domain $root_host does not resolve to the public IP of this server ($public_ip)"
  echo
  root_host_prev=$root_host
  read -p "Domain name [$root_host_prev]: " root_host
  if [ -z ${root_host} ]; then
    root_host=$root_host_prev
  fi
  public_ip=$(curl -s https://api.ipify.org)
  domain_ip=$(dig +short @1.1.1.1 ${root_host})

  # Patikriname iš naujo, ar `dig` grąžina reikšmę
  if [[ -z "$domain_ip" ]]; then
    echo "ERROR: Unable to resolve the domain $root_host. Check your DNS settings."
    exit 1
  fi
  echo
done

echo
echo "Running certbot in dry-run mode to test the validity of the domain..."
if [[ "$adguard_enable" =~ ^[yY]$ ]]; then
  $SUDO .venv/bin/certbot certonly --non-interactive --break-my-certs --force-renewal --agree-tos --email root@localhost.com --standalone --staging -d $root_host -d wg.$root_host -d auth.$root_host -d adguard.$root_host || $SUDO .venv/bin/certbot certonly --non-interactive --force-renewal --agree-tos --email root@localhost.com --standalone -d $root_host -d wg.$root_host -d auth.$root_host -d adguard.$root_host || exit
else
  $SUDO .venv/bin/certbot certonly --non-interactive --break-my-certs --force-renewal --agree-tos --email root@localhost.com --standalone --staging -d $root_host -d wg.$root_host -d auth.$root_host || $SUDO .venv/bin/certbot certonly --non-interactive --force-renewal --agree-tos --email root@localhost.com --standalone -d $root_host -d wg.$root_host -d auth.$root_host  || exit
fi
echo "OK"

echo "root_host: \"${root_host}\"" >> $HOME/ansible-easy-vpn/custom.yml

echo "What's your preferred DNS?"
echo
echo "1. Cloudflare [1.1.1.1] (default)"
echo "2. Quad9 [9.9.9.9]"
echo "3. Google [8.8.8.8]"
echo

read -p "DNS [1]: " dns_number

if [ -z ${dns_number} ] || [ ${dns_number} == "1" ]; then
    dns_nameservers="cloudflare"
    echo "Using default DNS: Cloudflare [1.1.1.1]"
else
  until [[ "$dns_number" =~ ^[2-3]$ ]]; do
    echo "Invalid DNS choice"
    echo "Make sure that you answer with either 1, 2 or 3"
    read -p "DNS [1]: " dns_number
  done
    case $dns_number in 
      "2")
        dns_nameservers="quad9"
        ;;
      "3")
        dns_nameservers="google"
        ;;
        *)
        dns_nameservers="cloudflare"
        ;;
    esac
fi

echo "dns_nameservers: \"${dns_nameservers}\"" >> $HOME/ansible-easy-vpn/custom.yml

if [[ ! $AWS_EC2 =~ true ]]; then
  echo
  echo "Would you like to use an existing SSH key?"
  echo "Press 'n' if you want to generate a new SSH key pair"
  echo
  read -p "Use existing SSH key? [y/N]: " new_ssh_key_pair
  until [[ "$new_ssh_key_pair" =~ ^[yYnN]*$ ]]; do
          echo "$new_ssh_key_pair: invalid selection."
          read -p "[y/N]: " new_ssh_key_pair
  done
  echo "enable_ssh_keygen: true" >> $HOME/ansible-easy-vpn/custom.yml

  if [[ "$new_ssh_key_pair" =~ ^[yY]$ ]]; then
    echo
    read -p "Please enter your SSH public key: " ssh_key_pair

    echo "ssh_public_key: \"${ssh_key_pair}\"" >> $HOME/ansible-easy-vpn/custom.yml
  fi
fi


echo
echo
echo "Would you like to set up the e-mail functionality?"
echo "It will be used to confirm the 2FA setup and restore the password in case you forget it."
echo
read -p "Set up e-mail? [y/N]: " email_setup

until [[ "$email_setup" =~ ^[yYnN]*$ ]]; do
  echo "Invalid selection."
  read -p "Set up e-mail? [y/N]: " email_setup
done

if [[ "$email_setup" =~ ^[yY]$ ]]; then
  # SMTP provider selection
  echo "Select your SMTP provider or enter a custom server:"
  echo "1. Office 365 (smtp.office365.com, TLS, port 587)"
  echo "2. Gmail (smtp.gmail.com, TLS, port 587)"
  echo "3. Yahoo Mail (smtp.mail.yahoo.com, SSL, port 465)"
  echo "4. Custom SMTP server"
  read -p "Enter your choice [1]: " smtp_choice
  smtp_choice=${smtp_choice:-1}

  case $smtp_choice in
    1)
      email_smtp_host="smtp.office365.com"
      email_protocol="TLS"
      email_smtp_port=587
      ;;
    2)
      email_smtp_host="smtp.gmail.com"
      email_protocol="TLS"
      email_smtp_port=587
      ;;
    3)
      email_smtp_host="smtp.mail.yahoo.com"
      email_protocol="SSL"
      email_smtp_port=465
      ;;
    4)
      # Custom SMTP server
      while true; do
        read -p "SMTP server: " email_smtp_host
        if [[ -n "$email_smtp_host" && "$email_smtp_host" =~ ^[a-zA-Z0-9._-]+$ ]]; then
          break
        fi
        echo "Invalid SMTP server: must contain only letters, numbers, dots, underscores, or hyphens."
        echo "You must provide a valid SMTP server address."
      done

      # Protocol selection for custom server
      while true; do
        echo "Choose e-mail protocol:"
        echo "1. TLS (default)"
        echo "2. SSL"
        echo "3. None (no encryption)"
        read -p "Enter your choice [1]: " protocol_choice
        protocol_choice=${protocol_choice:-1}

        case $protocol_choice in
          1)
            email_protocol="TLS"
            email_smtp_port=587
            break
            ;;
          2)
            email_protocol="SSL"
            email_smtp_port=465
            break
            ;;
          3)
            email_protocol="None"
            email_smtp_port=25
            break
            ;;
          *)
            echo "Invalid choice. Please select 1, 2, or 3."
            ;;
        esac
      done
      ;;
    *)
      echo "Invalid choice. Defaulting to Office 365."
      email_smtp_host="smtp.office365.com"
      email_protocol="TLS"
      email_smtp_port=587
      ;;
  esac

  # SMTP login
  while true; do
    read -p "SMTP login: " email_login
    if [[ -n "$email_login" ]]; then
      break
    fi
    echo "SMTP login cannot be empty."
  done

  # SMTP password (optional)
  read -s -p "SMTP password (press Enter to skip): " email_password
  echo

  # 'From' and 'To' e-mail
  read -p "'From' e-mail [${email_login}]: " email
  email=${email:-$email_login}

  read -p "'To' e-mail [${email_login}]: " email_recipient
  email_recipient=${email_recipient:-$email_login}

  # Write to custom.yml
  echo "email_smtp_host: \"${email_smtp_host}\"" >> $HOME/ansible-easy-vpn/custom.yml
  echo "email_smtp_port: \"${email_smtp_port}\"" >> $HOME/ansible-easy-vpn/custom.yml
  echo "email_protocol: \"${email_protocol}\"" >> $HOME/ansible-easy-vpn/custom.yml
  echo "email_login: \"${email_login}\"" >> $HOME/ansible-easy-vpn/custom.yml
  echo "email: \"${email}\"" >> $HOME/ansible-easy-vpn/custom.yml
  echo "email_recipient: \"${email_recipient}\"" >> $HOME/ansible-easy-vpn/custom.yml

  # Write password to secret.yml if provided
  if [[ -n "$email_password" ]]; then
    echo "email_password: \"${email_password}\"" >> $HOME/ansible-easy-vpn/secret.yml
  fi
fi


# Set secure permissions for the Vault file
touch $HOME/ansible-easy-vpn/secret.yml
chmod 600 $HOME/ansible-easy-vpn/secret.yml

if [ -z ${email_password+x} ]; then
  echo
else 
  echo "email_password: \"${email_password}\"" >> $HOME/ansible-easy-vpn/secret.yml
fi

if [[ $user_password =~ '"' ]]; then
  echo "user_password: '${user_password}'" >> $HOME/ansible-easy-vpn/secret.yml
else
  echo "user_password: \"${user_password}\"" >> $HOME/ansible-easy-vpn/secret.yml
fi


jwt_secret=$(openssl rand -hex 23)
session_secret=$(openssl rand -hex 23)
storage_encryption_key=$(openssl rand -hex 23)

echo "jwt_secret: ${jwt_secret}" >> $HOME/ansible-easy-vpn/secret.yml
echo "session_secret: ${session_secret}" >> $HOME/ansible-easy-vpn/secret.yml
echo "storage_encryption_key: ${storage_encryption_key}" >> $HOME/ansible-easy-vpn/secret.yml

echo
echo "Encrypting the variables"
if [[ ! -s $HOME/ansible-easy-vpn/secret.yml ]]; then
    echo "Error: secret.yml is empty or missing. Skipping encryption."
    exit 1
fi
ansible-vault encrypt $HOME/ansible-easy-vpn/secret.yml

echo
echo "Success!"
read -p "Would you like to run the playbook now? [y/N]: " launch_playbook
until [[ "$launch_playbook" =~ ^[yYnN]*$ ]]; do
				echo "$launch_playbook: invalid selection."
				read -p "[y/N]: " launch_playbook
done

if [[ "$launch_playbook" =~ ^[yY]$ ]]; then
  if [[ $EUID -ne 0 ]]; then
    echo
    echo "Please enter your current sudo password now"
    cd $HOME/ansible-easy-vpn && ansible-playbook --ask-vault-pass -K run.yml
  else
    cd $HOME/ansible-easy-vpn && ansible-playbook --ask-vault-pass run.yml
  fi
else
  echo "You can run the playbook by executing the bootstrap script again:"
  echo "cd ~/ansible-easy-vpn && bash bootstrap.sh"
  exit
fi
