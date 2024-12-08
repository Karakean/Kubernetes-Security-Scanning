# Zadanie 0. - przygotowanie środowiska laboratoryjnego.

### 1. Wymagania

W celu realizacji zadania należy przygotować środowisko wirtualne o następujących parametrach:
* Zalecany OS - Debian 12.8.0.
* Minimum 2 CPU,
* Minimum 8GB RAM,
* Minimum 16GB pamięci dyskowej.

Gotowy obraz maszyny wirtualnej przygotowany przez nas można pobrać za pomocą następującej komendy:

```bash
curl -O https://files.simmondobber.com/files/debian-binsh.ova
```

### 2. Uruchomienie środowiska (w przypadku wybrania naszego obrazu)

Do uruchomienia środowiska zalecamy narzędzie VirtualBox:

```bash
wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.virtualbox.org/virtualbox/debian $(lsb_release -cs) contrib"
sudo apt-get install -y virtualbox-7.0 
```

Pracujemy na użytkowniku root. Hasło to `kti`. Na maszynie znajdują się preinstalowane narzędzia przydatne min. do debugowania.

W celu nawiązania połączenia ssh pomiędzy hostem, a maszyną zalecamy stosowanie się do poradnika znajdującego się pod linkiem (https://dev.to/developertharun/easy-way-to-ssh-into-virtualbox-machine-any-os-just-x-steps-5d9i).

**Uwaga**: w udostępnionym przez nas środowisku zdarza się problem z nieprawidłowo działającym serwerem ssh. W celu naprawy należy przeinstalować pakiet przy użyciu następującej komendy:
```bash
apt --reinstall install openssh-server
```

# Zadanie 1. - prawidłowa inicjalizacja klastra kubernetes w oparciu o audyt control plane'a.

Zadanie polega na przygotowaniu środowiska pod klaster kubernetes, a następnie inicjalizację i wstępną konfigurację control plane'a zgodnie z zaleceniami narzędzia `kube-bench`.
Zadanie podzielone zostało na następujące fazy:
1. Przygotowanie środowiska pod klaster kubernetes - w tym podpunkcie pokrótce zapoznasz się z procesem konfiguracji środowiska systemowego wymaganym do prawidłowej inicjalizacji klastra.
2. Inicjalizacja klastra kubernetes - podzadanie ma na celu zapoznać Cię z konfiguracją zasobów niezbędnych do inicjalizacji klastra, procesem inicjalizacji oraz weryfikacją poprawnego działania.
3. Przeprowadzenie audytu control-plane'a klastra za pomocą narzędzia `kube-bench` - nauczysz się przeprowadzać audyt bezpieczeństwa przy pomocy narzędzia `kube-bench` oraz analizować jego rezultaty.
4. Poprawa problemów wypunktowanych przez kube-bench - na koniec zapoznasz się z poszczególnymi błędami konfiguracji, a następnie zajmiesz się usunięciem wykrytych problemów.

## Przygotowanie środowiska pod klaster kubernetes.

**Poniżej przedstawiono krok po kroku, jak skonfigurować środowisko do uruchomienia klastra Kubernetes na maszynie z systemem Linux.**

### 1. Aktualizacja systemu
Na początek należy zaktualizować system operacyjny, aby upewnić się, że wszystkie pakiety są w najnowszych wersjach:

```bash
apt-get update && apt-get upgrade -y
```

---

### 2. Instalacja i konfiguracja containerd
Containerd jest wymagany jako runtime dla kontenerów w Kubernetes. Aby go zainstalować i skonfigurować:

1. Zainstaluj containerd:

```bash
apt-get install -y containerd
```

2. Utwórz domyślny plik konfiguracyjny:

```bash
mkdir -p /etc/containerd
containerd config default > /etc/containerd/config.toml
```

3. Zmień ustawienie w pliku konfiguracyjnym, aby używał systemd jako managera grup kontrolnych (cgroups):

```bash
sed -i '/SystemdCgroup = false/c\SystemdCgroup = true' /etc/containerd/config.toml
```

4. Zrestartuj usługę containerd:

```bash
systemctl restart containerd
```

---

### 3. Konfiguracja systemowa
Wykonaj następujące kroki, aby przygotować system operacyjny:

1. Załaduj moduł jądra `br_netfilter`, który jest wymagany do zarządzania ruchem sieciowym Kubernetes:

```bash
echo 'br_netfilter' > /etc/modules-load.d/k8s.conf
modprobe br_netfilter
```

2. Wyłącz swap, ponieważ Kubernetes (control-plane) wymaga jego dezaktywacji:

```bash
swapoff -a
sed -i '/ swap / s/^/#/' /etc/fstab
```

3. Włącz przekazywanie pakietów IPv4:

```bash
sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p
```

---

### 4. Instalacja narzędzi Kubernetes
Aby zainstalować `kubeadm`, `kubelet` oraz `kubectl`, wykonaj poniższe kroki:

1. Zainstaluj wymagane pakiety:

```bash
apt-get install -y apt-transport-https ca-certificates curl gpg
```

2. Utwórz katalog do przechowywania kluczy:

```bash
mkdir -p /etc/apt/keyrings
```

3. Pobierz i zainstaluj klucz GPG dla repozytoriów Kubernetes:

```bash
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.31/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
```

4. Dodaj repozytorium Kubernetes do listy źródeł:

```bash
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.31/deb/ /' > /etc/apt/sources.list.d/kubernetes.list
```

5. Zaktualizuj listę dostępnych pakietów:

```bash
apt-get update
```

6. Zainstaluj `kubeadm`, `kubelet` oraz `kubectl`:

```bash
apt-get install -y kubeadm kubelet kubectl
```

---

## Inicjalizacja klastra kubernetes.

### 1. Utworzenie pliku zawierającego informacje o konfiguracji klastra

Do inicjalizacji klastra potrzebny jest podstawowy plik konfiguracyjny, w którym znajdą się niezbędne informacje takie jak na przykład adres IP przypisany do apiserwera.

1. Utwórz plik konfiguracyjny `kubeadm-config.yaml` w katalogu `/etc/kubernetes`:

**Uwaga: adres IP `10.0.2.15` należy podmienić (w obydwu miejscach) na adres swojego interfejsu sieciowego.**

[TODO: sprawdzic ifconfig]

```bash
mkdir -p /etc/kubernetes
tee /etc/kubernetes/kubeadm-config.yaml > /dev/null <<EOF
---
apiVersion: "kubeadm.k8s.io/v1beta4"
kind: "ClusterConfiguration"
kubernetesVersion: "v1.31.3"
controlPlaneEndpoint: "10.0.2.15" # Adres apiserwera
networking:
  podSubnet: "10.244.0.0/16" # Wewnętrzna podsieć klastra zarezerwowana dla podów
  serviceSubnet: "10.245.0.0/16" # Wewnętrzna podsieć klastra zarezerwowana dla serwisów
apiServer:
  certSANs:
    - "10.0.2.15" # Adres apiserwera uwzględniany w certyfikacie
EOF
```

---

### 2. Utworzenie certyfikatów

W celu poprawnego działania docelowej konfiguracji konieczne będzie utworzenie niestandardowych certyfikatów (w polu `X509v3 Subject Alternative Name` powinny zawierać wpis IP Address przypisany do apiserwera). Będzie to kolejno certyfikat `ca.crt` pełniący rolę CA klastra oraz podpisany przez niego certyfikat `kubelet.crt` służący do uwierzytelniania się kubeleta. Pozostałe certyfikaty wygenerują się automatycznie wraz z inicjalizacją klastra. Zmiany w certyfikatach będą niezbędne do realizacji dalszej części laboratorium.

1. Utwórz plik zawierający konfigurację certyfikatu CA:

**Uwaga: adres IP `10.0.2.15` należy podmienić na adres swojego interfejsu sieciowego.**

```bash
tee ca.cnf > /dev/null <<EOF
[ req ]
distinguished_name = req_distinguished_name 
x509_extensions = v3_ca
req_extensions = v3_req

[ req_distinguished_name ]
commonName = k8s_ca
commonName_default = Kubernetes

[ v3_ca ]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
subjectAltName = @alt_names

[ v3_req ]
keyUsage = keyCertSign, cRLSign
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = kubernetes
DNS.2 = kubernetes.default
DNS.3 = kubernetes.default.svc
DNS.4 = kubernetes.default.svc.cluster.local
IP.1 = 10.245.0.1 # [TODO: co to za adres?]
IP.2 = 10.0.2.15 
EOF
```

2. Wygeneruj klucz prywatny dla certyfikatu CA:

```bash
openssl genrsa -out ca.key 4096
```

3. Następnie, wygeneruj certyfikat CA, który będzie wykorzystywany do podpisywania innych certyfikatów:

```bash
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -config ca.cnf -extensions v3_ca
```
[TODO: You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
k8s_ca [Kubernetes]:.
Error: No objects specified in config file
Error making certificate request
]

4. Utwórz plik zawierający konfigurację certyfikatu kubeleta:

**Uwaga: adres IP `10.0.2.15` należy podmienić na adres swojego interfejsu sieciowego.**

```bash
tee kubelet.cnf > /dev/null <<EOF
[ req ]
default_bits       = 2048
default_keyfile    = /etc/kubernetes/pki/kubelet.key
distinguished_name = req_distinguished_name 
req_extensions     = v3_req

[ req_distinguished_name ]
CN = kubelet
commonName = k8s_kubelet
commonName_default = Kubernetes

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = kubernetes
DNS.2 = kubernetes.default
DNS.3 = kubernetes.default.svc
DNS.4 = kubernetes.default.svc.cluster.local
IP.1 = 10.245.0.1
IP.2 = 10.0.2.15 
EOF
```

5. W kolejnym kroru wygeneruj klucz prywatny dla kubeleta:

```bash
openssl genrsa -out kubelet.key 2048
```
[TODO: czemu tu krotszy?]

6. Po wygenerowaniu klucza prywatnego dla kubeleta, stwórz żądanie certyfikatu (CSR):

```bash
openssl req -new -key kubelet.key -out kubelet.csr -config kubelet.cnf
```

[TODO: ponownie; puste wartosci czy co?]

7. Na koniec, podpisz żądanie certyfikatu (`kubelet.csr`) certyfikatem CA `ca.crt`, aby wygenerować certyfikat dla kubeleta:

```bash
openssl x509 -req -in kubelet.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out kubelet.crt -days 365 -extensions v3_req -extfile kubelet.cnf
```

8. Obydwa pliki `.crt` oraz `.key` przenieś do katalogu `/etc/kubernetes/pki`:

```bash
mkdir -p /etc/kubernetes/pki
mv {*.crt,*.key} /etc/kubernetes/pki
```

---

### 3. Inicjalizacja klastra i CNI

Nadszedł czas na inicjalizację klastra. W tym celu wykorzystane zostanie narzędzie `kubeadm`, wraz z przygotowanymi wcześniej elementami konfiguracji. Jako CNI posłuży rozwiązanie `calico`.

1. Zainicjalizuj klaster przy pomocy narzędzie `kubeadm`:

```bash 
kubeadm init --config /etc/kubernetes/kubeadm-config.yaml
```

2. Umieść plik zawierający `kubeconfig` w katalogu użytkownika (root):

```bash
mkdir /root/.kube
cp /etc/kubernetes/admin.conf /root/.kube/config
```

Dzięki temu możliwa będzie komunikacja z klastrem.

3. Zainicjalizuj CNI korzystając z narzędzia `kubectl` wskazując adres URL odpowiedniego manifestu:

```bash
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.29.1/manifests/calico.yaml
```

4. W tym momencie zalecany jest restart maszyny.
```bash
reboot
```

5. Po ponownym uruchomieniu należy sprawdzić stan klastra.

**Uwaga: klaster może potrzebować trochę czasu, aby ponownie wstać.**

```bash
kubectl get pods -A # Komenda powinna zwrócić listę podów. Należy upewnić się, że wszystkie pody zostały utworzone.
kubectl get nodes -A # Dodatkowo należy upewnić się, że węzeł jest w stanie `READY` oznaczającym jego gotowość do działania.
```

---

## Przeprowadzenie audytu control-plane'a klastra za pomocą narzędzia `kube-bench`.

### 1. Uruchomienie audytu.

Sposobem, w jaki przeprowadzimy audyt będzie utworzenie zasobu typu `job` zawierającego narzędzie `kube-bench`. Następnie zbadamy rezultat audytu poprzez analizę logów zasobu.

1. Utwórz zasób typu `job` zawierający narzędzie `kube-bench` poprzez zaaplikowanie manifestu z odpowiedniego adresu URL:

```bash
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-master.yaml
```

2. Status ukończenia audytu można obserwować za pomocą narzędzia `kubectl`:

```bash
kubectl get jobs/kube-bench-master # Zmiana statusu na `Complete` jest równoważna z ukończeniem audytu.
```

3. W tym momencie możemy odczytać rezultat z logów zasobu:

```bash
kubectl logs jobs/kube-bench-master
```

Pomocne może okazać się umieszczenie logów w pliku oraz zastosowanie narzędzia umożliwiającego odczyt wraz ze stronnicowaniem (np. `less`).

```bash
kubectl logs jobs/kube-bench-master > logs.txt
less logs.txt
```

### 2. Analiza rezultatu

Początkowa część zawiera informacje o przeprowadzonych testach. Wyróżnić możemy cztery kategorie testów:
* Control Plane Security Configuration (1.1.x),
* API Server (1.2.x),
* Controller Manager (1.3.x),
* Scheduler (1.4.x).

Na początku każdego testu istnieje informacja o jego rezultacie:
* [INFO] - linia zawierająca informację kontrolną (pomijamy),
* [PASS] - test automatyczny zakończony się pomyślnie,
* [WARN] - test manualny, który powinien zostać wykonany ręcznie (w naszym zadaniu nie będziemy zajmować się testami manualnymi, jednakże w praktyce zdecydowanie nie powinny być one ignorowane),
* [FAIL] - test automatyczny zakończony niepowodzeniem (to właśnie na tych testach będziemy chcieli się skupić).

Dalsza część logów zawiera bardziej szczegółowe informacje dotycznące testów manualnych oraz niezaliczonych testów automatycznych. Na końcu widnieje podsumowanie audytu. 

Warto zaznaczyć, że w zadaniu laboratoryjnym ograniczamy się jedynie do audytu control plane'a; w celu przeprowadzenia bardziej obszernego audytu należy wykorzystać inne zasoby udostępniane przez twórców narzędzia `kube-bench`. Zainteresowanych odsyłamy do repozytorium (https://github.com/aquasecurity/kube-bench), gdzie znajdują się pozostałe manifesty.

W dalszym ciągu zadania postaramy się naprawić wszystkie testy zakończone niepowodzeniem `[FAIL]`. W celu wygodnego ponawiania audytu zalecamy utworzenie skryptu, który usunie stary zasób i utworzy na jego miejsce nowy:

```bash
tee ./test.sh > /dev/null <<EOF
#!/bin/bash

set -eu

kubectl delete job kube-bench-master --ignore-not-found=true # Usuń poprzednią instancję zasobu (jeśli istnieje)
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-master.yaml # Utwórz nową instancję zasobu

while true; do # Czekaj na zakończenie zadania
  status=$(kubectl get job kube-bench-master -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}')
  if [ "$status" == "True" ]; then
    break
  fi
  sleep 1
done

kubectl logs job/kube-bench-master | grep '\[FAIL\]' > logs.txt # Pobierz logi, a następnie zapisz do pliku informacje o testach zakończonych niepowodzeniem

less logs.txt # Wyświetl listę testów zakończonych niepowodzeniem
EOF
```

## Poprawa problemów wypunktowanych przez kube-bench.

### 1. Ustawienie właściciela katalogu danych etcd
**Błąd:**  
1.1.12 Ensure that the etcd data directory ownership is set to etcd:etcd

**Opis:**  
Katalog danych etcd (`/var/lib/etcd`) powinien należeć do użytkownika i grupy `etcd`, aby zapewnić właściwe bezpieczeństwo danych.

**Działanie:**  
Utwórz grupę oraz użytkownika etcd ustawiając /var/lib/etcd jako katalog domowy oraz wyłącz możliwość logowania się na konto:
```bash
groupadd --system etcd
useradd --system --home-dir /var/lib/etcd --shell /sbin/nologin --gid etcd etcd
```

Ustaw właściciela katalogu:

```bash
chown -R etcd:etcd /var/lib/etcd
```

**Rezultat:**  
Katalog `/var/lib/etcd` powinien posiadać dostęp ograniczony do użytkownika etcd.

---

### 2. Ustawienie argumentu `--kubelet-certificate-authority`
**Błąd:**  
1.2.5 Ensure that the --kubelet-certificate-authority argument is set as appropriate

**Opis:**  
Argument `--kubelet-certificate-authority` w konfiguracji apiserwera powinien wskazywać na plik certyfikatu autorytetu (CA). Zapewnia to, że apiserwer używa tylko certyfikatów podpisanych przez zaufany CA.

**Działanie:**  
W pliku konfiguracyjnym apiserwera ( `/etc/kubernetes/manifests/kube-apiserver.yaml`) upewnij się, że istnieje linia: `--kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt`. [TODO w containers command]

Zrestartuj kubelet:

```bash
systemctl restart kubelet
```

**Rezultat:**  
Wywołanie komendy `kubectl logs -n kube-system etcd-debian` powinno zakończyć się niepowodzeniem weryfikacji certyfikatu. Dzieje się tak, gdyż kubelet nie może uwierzytelnić się apiserwerowi. Należy więc dodać kubeletowi certyfikat podpisany przez CA wyspecyfikowane w apiserwerze.

**Następne Działanie:**  
W pliku konfiguracyjnym kubeleta (`/var/lib/kubelet/config.yaml`) dopisz następujące linie specyfikujące certyfikat używany do komunikacji z apiserwerem:
```
tlsCertFile: /etc/kubernetes/pki/kubelet.crt
tlsPrivateKeyFile: /etc/kubernetes/pki/kubelet.key
```
[TODO: w jakim bloku?]
Zrestartuj kubelet: `systemctl restart kubelet`.

**Rezultat:**  
Połączenie powinno być prawidłowo zabezpieczone. Komunikacja pomiędzy kubeletem oraz apiserwerem powinna być możliwa.

---

### 3. Wyłączenie profilowania na poziomie apiserwera

**Uwaga: podpunkt 3. korzystnie jest realizować wraz z podpunktami 4 oraz 5.**

**Błąd:**  
1.2.15 Ensure that the --profiling argument is set to false

**Opis:**  
Profilowanie w apiserwerze nie powinno być włączone, aby zminimalizować możliwość ujawnienia danych diagnostycznych.

**Działanie:**  
Zmodyfikuj konfigurację apiserwera (`/etc/kubernetes/manifests/kube-apiserver.yaml`), aby zawierała linię: `--profiling=false`.

Zrestartuj kubelet.

**Rezultat:**  
Profilowanie powinno zostać wyłączone.

---

### 4. Wyłączenie profilowania na poziomie controller-managera
**Błąd:**  
1.3.2 Ensure that the --profiling argument is set to false

**Opis:**  
Profilowanie w controller-managerze powinno być wyłączone, aby uniknąć potencjalnego ujawnienia szczegółowych informacji diagnostycznych.

**Działanie:**  
Zmodyfikuj konfigurację controller-managera (`/etc/kubernetes/manifests/kube-controller-manager.yaml`), aby zawierała linię: `--profiling=false`.

Zrestartuj kubelet.

**Rezultat:**  
Profilowanie powinno zostać wyłączone.

---

### 5. Wyłączenie profilowania na poziomie schedulera
**Błąd:** 1.4.1 Ensure that the --profiling argument is set to false

**Opis:**  
Profilowanie w schedulerze powinno być wyłączone, aby uniknąć potencjalnego ujawnienia szczegółowych informacji diagnostycznych.

**Działanie:**  
Zmodyfikuj konfigurację schedulera (`/etc/kubernetes/manifests/kube-scheduler.yaml`), aby zawierała linię: `--profiling=false`.

Zrestartuj kubelet.

**Rezultat:**  
Profilowanie powinno zostać wyłączone.

---

### 6. Ustawienie argumentu `--audit-log-path`

**Uwaga: podpunkt 6. korzystnie jest realizować wraz z podpunktami 7, 8 oraz 9.**

**Błąd:**  
1.2.16 Ensure that the --audit-log-path argument is set

**Opis:**  
Kubernetes powinien rejestrować zdarzenia audytu w określonym pliku, aby zapewnić zgodność i możliwość analizy zdarzeń.

**Działanie:**

Utwórz katalog na logi kubernetesa:  
```bash
mkdir -p /var/log/kubernetes
touch /var/log/kubernetes/audit.log` [TODO: usunac to]
chmod 644 /var/log/kubernetes/audit.log
```
Dodaj następującą opcję do pliku konfiguracyjnego apiserwera: `--audit-log-path=/var/log/kubernetes/audit.log`

Zrestartuj kubelet.

---

### 7. Konfiguracja `--audit-log-maxage`
**Błąd:** 1.2.17 Ensure that the --audit-log-maxage argument is set to 30 or as appropriate

**Opis:**  
Argument ten określa maksymalną liczbę dni przechowywania plików audytowych, co pomaga zarządzać przestrzenią dyskową.

**Działanie:**  
Dodaj do pliku konfiguracyjnego apiserwera: `--audit-log-maxage=30`

Zrestartuj kubelet.

---

### 8. Konfiguracja `--audit-log-maxbackup`
**Błąd:** 1.2.18 Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate

**Opis:**  
Argument ten ustala maksymalną liczbę kopii zapasowych plików audytowych, co pomaga w zarządzaniu miejscem na dysku.

**Działanie:**  
Dodaj do pliku konfiguracyjnego Aapiserwera: `--audit-log-maxbackup=10`

Zrestartuj kubelet.

---

### 9. Konfiguracja `--audit-log-maxsize`
**Błąd:** 1.2.19 Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate

**Opis:**  
Argument ten określa maksymalny rozmiar plików audytowych w megabajtach, aby kontrolować zużycie dysku.

**Działanie:**  
Dodaj do pliku konfiguracyjnego apiserwera: `--audit-log-maxsize=100`

Zrestartuj API server.

[TODO: JAK? kubectl delete kube-apiserver-debian?]

---

Po ponownym przeprowadzeniu audytu wszystkie błędy wykryte przez testy automatyczne powinny zostać rozwiązane.

W celu weryfikacji wykonania zadania w raporcie zamieść katalog `/etc/kubernetes` oraz plik `/var/lib/kubelet/config.yaml`.

Za wszelkie aktywności nadobowiązkowe (przykładowo: przeprowadzenie testów manualnych wypunktowanych przez `kube-bench`) przewidziane są dodatkowe punkty :).

---

# Zadanie 2. - izolacja sieci w systemie Kubernetes
Zadanie polega na odizolowaniu odpowiednich komponentów systemu Kubernetes na poziomie sieciowym z wykorzystaniem Network Policies.
Zadanie podzielone zostało na następujące fazy:
1. Wcielisz się w rolę developera i wykonasz deployment swojej prostej aplikacji webowej wraz z bazą danych. 
2. Wcielisz się w rolę atakującego i wykorzystasz domyślny brak izolacji podów w systemie Kubernetes wykonując atak na bazę danych, która została stworzona w ramach zadania pierwszego.
3. Wcielisz się w rolę administratora systemu Kubernetes i z wykorzystaniem odpowiednich narzędzi wykryjesz brak odpowiedniej izolacji sieci.
4. Wciąż jako administrator wprowadzisz odpowiednią izolację sieci z wykorzystaniem Network Policies.
5. Ponownie wcielisz się w rolę atakującego, aby powtórzyć atak.

## 1. Deployment aplikacji webowej oraz bazy danych

W ramach tej części zadania wcielamy się w rolę developera, który chce wykonać deployment swojej aplikacji webowej wykorzystującą bazę danych.

### 1. Tworzenie namespace
W pierwszej kolejności musimy stworzyć namespace w ramach którego będziemy wdrażać swoje zasoby.
Tworzymy plik o nazwie task-2-namespace.yaml z następującą zawartością:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: task-2-namespace
  labels:
    networking/namespace: task-2-namespace
```
Zasób tworzymy poprzez wykonanie komendy
`kubectl apply -f task-2-namespace.yaml`

### 2. Wdrażanie bazy danych
Następnie wdrażamy odpowiedniego poda z naszą bazą danych. Tworzymy plik database-pod.yaml z następującą zawartością:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: database-pod
  namespace: task-2-namespace
  labels:
    app: database-pod
spec:
  tolerations:
    - key: "node-role.kubernetes.io/control-plane"
      operator: "Exists"
      effect: "NoSchedule"
    - key: "node-role.kubernetes.io/control-plane"
      operator: "Exists"
  containers:
  - name: database-container
    image: ghcr.io/karakean/kubernetes-security-database
    ports:
    - containerPort: 5432
    env:
    - name: POSTGRES_USER
      value: "user"
    - name: POSTGRES_PASSWORD
      value: "password"
    - name: POSTGRES_DB
      value: "database"
```
Uwaga! W rzeczywistym scenariuszu danych wrażliwych nie podajemy w postaci jawnej, służą do tego sekrety Kubernetesowe.
Ponownie zasób tworzymy wykonując komendę `kubectl apply -f <NAZWA_PLIKU>`. Dotyczy to też wszystkich następnych kroków gdzie będziemy tworzyć zasoby poprzez manifesty YAMLowe.

Następnie potrzebujemy service typu ClusterIP przez który komunikować będziemy się z naszą bazą danych. Tworzymy plik database-service.yaml z poniższą zawartością:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: database-service
  namespace: task-2-namespace
spec:
  ports:
  - port: 5432
    targetPort: 5432
  selector:
    app: database-pod
```

### 3. Wdrażanie aplikacji webowej
Tworzymy obiekt typu deployment dla naszej aplikacji webowej poprzez stworzenie pliku web-app-deployment.yaml z zawartością jak poniżej:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app-deployment
  namespace: task-2-namespace
  labels:
    app: web-app-deployment
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web-app-pod
  template:
    metadata:
      labels:
        app: web-app-pod
    spec:
      tolerations:
        - key: "node-role.kubernetes.io/control-plane"
          operator: "Exists"
          effect: "NoSchedule"
        - key: "node-role.kubernetes.io/control-plane"
          operator: "Exists"
      containers:
        - name: web-app-container
          image: ghcr.io/karakean/kubernetes-security-web-app
          ports:
            - containerPort: 3000
          env:
            - name: DB_USER
              value: "user"
            - name: DB_PASSWORD
              value: "password"
            - name: DB_HOST
              value: "database-service"
            - name: DB_NAME
              value: "database"
            - name: DB_PORT
              value: "5432"
            - name: PORT
              value: "3000"
```
Uwaga! W rzeczywistym scenariuszu danych wrażliwych nie podajemy w postaci jawnej, służą do tego sekrety Kubernetesowe.
Jak możemy zauważyć dane do logowania do naszej bazy nie są zbyt bezpieczne. W dalszej części zadania, wcielając się w postać atakującego, wykorzystamy ten fakt.

Następnie potrzebujemy service typu NodePort który umożliwi nam komunikację z naszą aplikacją z zewnątrz klastra. Tworzymy plik web-app-service.yaml z poniższą zawartością:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: web-app-service
  namespace: task-2-namespace
spec:
  type: NodePort
  ports:
  - nodePort: 30001
    port: 3000
    targetPort: 3000
  selector:
    app: web-app-pod
```

### 4. Logowanie

W przeglądarce wpisujemy adres `http://localhost:XX31`, gdzie `XX` to dwie ostatnie cyfry naszego numeru indeksu.
Naszym oczom ukazuje się ekran logowania do którego wprowadzamy wymyślone przez siebie dane.
Uwaga! Nie należy wprowadzać swoich prawdziwych loginów i haseł!
Po zalogowaniu powinniśmy uzyskać komunikat o pomyślnym zalogowaniu.
Wykonujemy zrzut ekranu i nazywamy go XXXXXX_zad2_1.jpg, gdzie XXXXXX to nasz numer indeksu. 

## 2. Atak na bazę danych

W ramach drugiego podzadania wcielimy się w rolę atakującego i wykonamy atak na uprzednio wdrożoną bazę danych.

### 1. Tworzenie środowiska ataku
Tworzymy plik attacker-pod.yaml o poniższej zawartości:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: task-2-namespace
  labels:
    app: attacker-pod
spec:
  tolerations:
    - key: "node-role.kubernetes.io/control-plane"
      operator: "Exists"
      effect: "NoSchedule"
    - key: "node-role.kubernetes.io/control-plane"
      operator: "Exists"
  containers:
    - name: alpine-linux
      image: alpine:3.20
      command: ["sh", "-c", "apk add --no-cache postgresql-client && sleep 3600"]
```

### 2. Uzyskanie adresu IP
Poprzez wykonanie komendy `kubectl get pods -o wide -n task-2-namespace` uzyskujemy adres IP poda z bazą danych. W rzeczywistym scenariuszu ataku adres ten moglibyśmy uzyskać np. poprzez skanowanie sieci.

### 3. Wykonanie ataku
Na poda pełniącego funkcję naszego środowiska do ataku dostajemy się z wykorzystaniem komendy `kubectl exec -it attacker-pod -n task-2-namespace -- /bin/sh`.
Po pomyślnym wejściu do poda mozna sprawdzić łączność z bazą danych poleceniem `ping <ADRES_IP_BAZY_DANYCH>`.
W celu połączenia z bazą danych wykonujemy komendę:
`psql -h <ADRES_IP_BAZY_DANYCH> -p 5432 -U <NAZWA_UŻYTKOWNIKA> -d database`
gdzie w `<ADRES_IP_BAZY_DANYCH>` wprowadzamy uzyskany adres IP poda bazy danych, zaś w polu `<NAZWA_UŻYTKOWNIKA>` oraz haśle wprowadzamy użyte wcześniej przy wdrażaniu sekretne wartości, które ze względu na prostotę nie byłyby zbyt skomplikowane do odgadnięcia dla rzeczywistego atakującego.

Po podłączeniu się do bazy wykonujemy komendę:
`SELECT * FROM users;`
Wykonujemy zrzut ekranu i nazywamy go XXXXXX_zad2_2.jpg, gdzie XXXXXX to nasz numer indeksu.
Po wykonaniu proszę wyjść z poda komendą exit a następnie usunąć go komendą `kubectl delete pod <NAZWA_PODA> -n <NAZWA_NAMESPACE>`.

## 3. Skan systemu

W tej części zadania wcielamy się w administratora systemu Kubernetes, który przeprowadzi skan celem wykrycia niewystarczającej izolacji sieci.

### 1. Pobranie narzędzi do skanowania sieci
W pierwszej kolejności należy pobrać narzędzie, które umożliwi nam wykrycie braku izolacji sieci na poziomie komunikacji między podami w systemie Kubernetes.

Dla przykładu może, ale nie musi, być to narzędzie Kubescape, które instalujemy za pomocą poniższej komendy. Komenda zainstaluje narzędzie oraz przeprowadzi ogólny skan:
`curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash`

### 2. Przeprowadzenie skanu pod kątem braku polityk sieciowych

W celu uzyskania dokładniejszych informacji odnośnie polityk sieciowych w naszym namespace z narzędziem Kubescape wykonujemy skan z opcjami jak poniżej:
`kubescape scan control C-0260 -v --include-namespaces task-2-namespace`

Niezależnie od wykorzystanego narzędzia proszę załączyć odpowiedni zrzut ekranu jako dowód wykrycia braku izolacji sieci w naszym namespace.
Proszę nazwać go XXXXXX_zad2_3.jpg, gdzie XXXXXX to nasz numer indeksu.

## 4. Wprowadzenie izolacji sieci

W ramach tego zadania, wciąż jako administrator systemu Kubernetes, wprowadzimy odpowiednią izolację sieci zgodnie z uwagami uzyskanymi od narzędzi skanujących.

### 1. Zastosowanie izolacji dla bazy danych
Tworzymy network policy dla bazy danych z wykorzystaniem poniższego pliku database-network-policy.yaml, izolując całkowicie ruch wyjściowy a ruch wejściowy ograniczając do aplikacji webowej.
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: database-network-policy
  namespace: task-2-namespace
spec:
  podSelector:
    matchLabels:
      app: database-pod
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
      - namespaceSelector:
          matchLabels:
            networking/namespace: task-2-namespace
        podSelector:
          matchLabels:
            app: web-app-pod
      ports:
        - protocol: TCP
          port: 5432
```

### 2. Zastosowanie izolacji dla aplikacji webowej
W przypadku aplikacji webowej dopuścimy każdy ruch wejściowy, ale ruch wyjściowy jedynie do bazy danych oraz DNS (port 53).
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-app-network-policy
  namespace: task-2-namespace
spec:
  podSelector:
    matchLabels:
      app: web-app-pod
  policyTypes:
    - Egress
    - Ingress
  ingress:
    - from: []
      ports:
        - protocol: TCP
          port: 3000
  egress:
    - to:
      - namespaceSelector:
          matchLabels:
            networking/namespace: task-2-namespace
        podSelector:
          matchLabels:
            app: database-pod
      ports:
        - protocol: TCP
          port: 5432
    - to:
      ports:
        - protocol: TCP
          port: 53
        - protocol: UDP
          port: 53
```
Proszę ponownie w przeglądarce wpisać adres `http://localhost:XX31`, gdzie `XX` to dwie ostatnie cyfry naszego numeru indeksu i upewnić się, że proces logowania nadal działa.

### 3. Powtórny skan
Proszę powtórzyć skan (z punktu 3.2) a zrzut ekranu wynikowego skanu nazwać XXXXXX_zad2_4.jpg, gdzie XXXXXX to nasz numer indeksu.

## 5. Powtórny atak na bazę danych

W tej fazie zadania powracamy do roli atakującego i ponownie próbujemy wykonać atak na bazę danych.
Proszę wykonać kroki analogiczne do punktu 2.
Czy atak się powiódł? Dlaczego otrzymaliśmy taki rezultat? Proszę odpowiedzieć w 1-2 zdaniach i swoje wnioski spisać w pliku XXXXXX_zad2_wnioski.txt, gdzie XXXXXX to nasz numer indeksu.

## 6. Zastosowanie domyślnej polityki sieciowej dla namespace

### 1. Skan pod kątem domyślnej polityki sieciowej dla namespace

Podobnie jak w przypadku firewalli, dobrą praktyką jest blokada wszelkiego ruchu sieciowego poza tym bezpośrednio zadeklarowanym jako dopuszczonym.
W ten sposób pody w naszym namespace nie będą domyślnie wystawione na ataki, wynikające z niewystarczającej izolacji, opisane w ramach tego zadania.
Możemy wprowadzić taką domyślną politykę odrzucania dla wszystkich podów w namespace. 
W pierwszej kolejności jednak wykryjemy jej brak za pomocą odpowiedniego narzędzia.

Dla przykładu może, ale nie musi, być to narzędzie kubeaudit, które instalujemy wykonując poniższe komendy:
```bash
curl -LO https://github.com/Shopify/kubeaudit/releases/download/v0.22.2/kubeaudit_0.22.2_linux_amd64.tar.gz
tar -xvf kubeaudit_0.22.2_linux_amd64.tar.gz
chmod +x kubeaudit
mv kubeaudit /usr/local/bin/
```

Następnie wykonujemy skan naszego namespace pod kątem braku domyślnej polityki `deny`.
Dla narzędzie kubeaudit, przy założeniu, że definicja naszego namespace znajduje się w pliku `task-2-namespace.yaml`, jest to następująca komenda:
`kubeaudit netpols -f task-2-namespace.yaml`.

Proszę wykonać zrzut ekranu prezentujący wynik takiego skanowania i nazwać go XXXXXX_zad2_6.jpg, gdzie XXXXXX to nasz numer indeksu.

### 2. Zastosowanie domyślnej polityki sieciowej dla namespace
Proszę zmodyfikować zawartość pliku `task-2-namespace.yaml` na tę widoczną ponizej:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: task-2-namespace
  labels:
    networking/namespace: task-2-namespace

---

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: task-2-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```
oraz zastosować komendą `kubectl apply -f`

### 2. Powtórny skan
Proszę ponownie wykonać skan naszego namespace pod kątem braku domyślnej polityki `deny`, analogicznie jak w punkcie 6.1.
Proszę wykonać zrzut ekranu prezentujący wynik takiego skanowania i nazwać go XXXXXX_zad2_7.jpg, gdzie XXXXXX to nasz numer indeksu.

## 7. Konsolidacja plików wynikowych
Zrzuty ekranu oraz wnioski spakować w plik zip. [TODO: jak zbieramy?]