# Wstęp teoretyczny

## Czym jest Kubernetes?
Kubernetes to platforma umożliwiająca zarządzanie kontenerami rozproszonymi po wielu serwerach, automatyzująca jednocześnie zarządzanie, skalowanie i wdrażanie aplikacji skonteneryzowanych.

## Architektura systemu Kubernetes

### Klaster Kubernetes
Klaster Kubernetes to zbiór zasobów, które współpracują w celu uruchamiania i zarządzania aplikacjami kontenerowymi. Składa się z:

1. **Węzłów Control Plane**:
   - Odpowiadają za zarządzanie klastrem i jego konfiguracją.
   - Kluczowe komponenty węzłów Control Plane:
     - **Kube-API Server**: Obsługuje żądania API od użytkowników i innych komponentów klastra. Jest centralnym punktem komunikacji.
     - **Etcd**: Rozproszona baza danych klucz-wartość, w której przechowywany jest stan klastra (np. informacje o podach, konfiguracjach).
     - **Controller Manager**: Zawiera różne kontrolery, takie jak kontroler replikacji, który zapewnia odpowiednią liczbę podów.
     - **Kube-Scheduler**: Decyduje, na którym węźle roboczym uruchomić nowe pody, biorąc pod uwagę dostępne zasoby i wymagania aplikacji.
   - Zdarza się, że w środowiskach produkcyjnych występuje więcej niż jeden węzeł Control Plane, aby zapewnić wysoką dostępność (High Availability).

2. **Węzłów roboczych (Worker Nodes)**:
   - Są odpowiedzialne za uruchamianie aplikacji kontenerowych.
   - Kluczowe komponenty węzłów roboczych:
     - **Kubelet**: Agenta, który zarządza podami na węźle i komunikuje się z Control Plane.
     - **Container Runtime**: Narzędzie odpowiedzialne za uruchamianie i zarządzanie kontenerami (np. containerd, CRI-O).
     - **Kube-Proxy**: Odpowiada za implementację reguł sieciowych, umożliwiając komunikację między podami i usługami.

**Uwaga! W ramach laboratorium ze względu na sprzętowo-zasobowe ograniczenia stosujemy konfigurację jednowęzłową; w rzeczywistości powinny być przynajmniej dwa węzły; jeden Control Plane i jeden Worker Node.** 

### Kluczowe obiekty Kubernetes
- **Pody**: Najmniejsza jednostka uruchomieniowa w Kubernetes, która może zawierać jeden lub więcej kontenerów współdzielących sieć i przestrzeń dyskową.
- **ReplicaSets**: Zarządza liczbą replik podów, zapewniając ich określoną liczbę w klastrze.
- **Deploymenty**: Ułatwiają zarządzanie aplikacjami, umożliwiając ich deklaratywne wdrażanie, aktualizacje i rollbacki.
- **Usługi (Services)**: Abstrakcja nad podami, zapewniająca stały punkt dostępu do aplikacji, niezależnie od zmian w liczbie podów.
- **Namespace**: Logiczna izolacja zasobów w klastrze, umożliwiająca organizację aplikacji oraz zarządzanie uprawnieniami.

---

## Narzędzia do analizy bezpieczeństwa Kubernetes

### kube-bench
- **Typ analizy**: Dynamiczna.
- **Benchmarki**: CIS Kubernetes Benchmark.
- **Opis**: Analizuje konfigurację Kubernetes pod kątem zgodności z wytycznymi bezpieczeństwa. Ocena obejmuje kontrolę Control Plane, węzłów roboczych i zasobów klastrowych.

### kubeaudit
- **Typ analizy**: Statyczna i dynamiczna.
- **Opis**: Wykrywa luki w konfiguracji zasobów Kubernetes, takie jak brak Network Policies, nieprawidłowe konfiguracje RBAC czy brak Security Context.

### kube-linter
- **Typ analizy**: Statyczna.
- **Opis**: Analizuje pliki YAML oraz Helm Charty pod kątem błędów i nieoptymalnych konfiguracji. Ocenia m.in. brak limitów zasobów, nieodpowiednie ustawienia bezpieczeństwa oraz nadmiarowe uprawnienia.

### kubescape
- **Typ analizy**: Statyczna i dynamiczna.
- **Benchmarki**: NSA-CISA Kubernetes Hardening Guidance, MITRE ATT&CK, CIS Kubernetes Benchmark.
- **Opis**: Kompleksowo skanuje klaster pod kątem zgodności z wytycznymi bezpieczeństwa, identyfikuje potencjalne zagrożenia i generuje szczegółowe raporty.

### Polaris
- **Typ analizy**: Statyczna i dynamiczna.
- **Opis**: Analizuje pliki YAML oraz wdrożone zasoby Kubernetes w kontekście dobrych praktyk bezpieczeństwa, takich jak właściwa konfiguracja Security Context czy limity zasobów.

---

## PersistentVolume (PV) i PersistentVolumeClaim (PVC)
**PersistentVolume (PV)** to zasób Kubernetes reprezentujący zewnętrzne miejsce przechowywania danych, takie jak dysk lokalny lub system plików sieciowych. **PersistentVolumeClaim (PVC)** to żądanie użytkownika na określoną przestrzeń dyskową, które jest powiązane z PV, jeśli spełnia jego wymagania.

---

## Security Context
Security Context definiuje specyficzne ustawienia bezpieczeństwa dla podów i kontenerów, m.in.:
- Uruchamianie procesów jako określony użytkownik.
- Wymuszanie uruchamiania procesów jako użytkownik bez uprawnień roota.
- Blokowanie możliwości eskalacji uprawnień w kontenerach.

Poprawna konfiguracja Security Context zmniejsza ryzyko ataków typu privilege escalation.

---

## Network Policies

### Domyślne zachowanie
Domyślnie Kubernetes nie stosuje izolacji sieciowej, co oznacza, że wszystkie pody w klastrze mogą komunikować się ze sobą bez ograniczeń. Deklarowanie Network Policies zmienia to zachowanie:
- Zadeklarowanie reguł typu Ingress lub Egress wprowadza domyślne odrzucenie ruchu, który nie jest jawnie dozwolony.
- Brak zadeklarowanych reguł oznacza brak ograniczeń w komunikacji sieciowej.

### Kluczowe elementy Network Policies
1. **PodSelector**: Wskazuje, które pody są objęte regułami.
2. **NamespaceSelector**: Umożliwia stosowanie reguł dla podów w określonych namespace'ach.
3. **PolicyTypes**:
   - Ingress (ruch przychodzący),
   - Egress (ruch wychodzący).
4. **Ports**: Określa dozwolone porty i protokoły.

Network Policies są kluczowe dla zapewnienia izolacji między aplikacjami i minimalizacji ryzyka ataków sieciowych.

---

## Role-Based Access Control (RBAC)

RBAC to mechanizm kontroli dostępu oparty na przypisywaniu ról użytkownikom lub aplikacjom w Kubernetes. 

### Kluczowe elementy RBAC
- **Role**: Uprawnienia przypisane w obrębie jednego namespace.
- **ClusterRole**: Uprawnienia obejmujące cały klaster.
- **RoleBinding/ClusterRoleBinding**: Przypisuje Role lub ClusterRole użytkownikom, grupom lub kontom serwisowym.

RBAC pozwala na precyzyjne zarządzanie dostępem do zasobów w klastrze, minimalizując ryzyko nieautoryzowanego dostępu i eskalacji uprawnień.


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

W celu nawiązania połączenia ssh pomiędzy hostem, a maszyną należy wejść w ustawieniach VirtualBoxa w sekcję Network/Adapter z NAT'em/Advanced/Port Forwarding i dodajesz nowy wpis z konkretnymi wartościami w odpowiednich polach:
- name: ssh,
- protocol: TCP,
- Host IP: (zostaje puste),
- Host Port: XX22, gdzie XX to dwie ostatnie cyfry Twojego numeru indeksu
- Guest IP: (zostaje puste),
- Guest Port: 22

Po konfiguracji w celu wejścia na maszynę poprzez SSH należy użyć komendy:
`ssh -p XX22 localhost`, gdzie XX to dwie ostatnie cyfry Twojego numeru indeksu 

**Uwaga**: w udostępnionym przez nas środowisku zdarza się problem z nieprawidłowo działającym serwerem ssh. W celu naprawy należy przeinstalować pakiet przy użyciu następującej komendy:
```bash
apt --reinstall install openssh-server
```

### 3. Agregowanie rezultatów wykonanych zadań
W ramach poszczególnych zadań będzie należało zebrać odpowiednie efekty wykonanej pracy w postaci np. plików, zrzutów ekranu czy wniosków w formie tekstowej. Prosimy aby pliki te zorganizować w cztery foldery (zad1, zad2, zad3, zad4) i do każdego z folderów umieszczać rezultaty odpowiadającego mu zadania. Całość następnie należy zagregować do jednego folderu o nazwie odpowiadającej Twojemu numerowi indeksu, po czym skompresować do formatu zip. Dla przykładu; student o numerze indeksu 123456 powinien przesłać plik 123456.zip w którym znajdować się będzie folder 123456 z czterema podfolderami (zad1, zad2, zad3, zad4), a w każdym podfolderze pliki potwierdzające wykonanie zadania.

# Zadanie 1 - prawidłowa inicjalizacja klastra kubernetes w oparciu o audyt control plane'a.

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

**Uwaga: adres IP `10.0.2.15` należy podmienić (w obydwu miejscach) na adres swojego interfejsu sieciowego. Adres możemy uzyskać poleceniem `ifconfig`**

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
IP.1 = 10.245.0.1
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
Wybieramy domyślne wartości wciskając enter bez wpisywania żadnych znaków.

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

6. Po wygenerowaniu klucza prywatnego dla kubeleta, stwórz żądanie certyfikatu (CSR):

```bash
openssl req -new -key kubelet.key -out kubelet.csr -config kubelet.cnf
```
Ponownie wybieramy domyślne wartości wciskając enter bez wprowadzania żadnych znaków.

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
W pliku konfiguracyjnym apiserwera ( `/etc/kubernetes/manifests/kube-apiserver.yaml`) upewnij się, że w bloku command istnieje linia: `--kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt`.

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
touch /var/log/kubernetes/audit.log
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

Zrestartuj kubelet oraz API server komendą `systemctl restart kubelet`.

---

Po ponownym przeprowadzeniu audytu wszystkie błędy wykryte przez testy automatyczne powinny zostać rozwiązane.

W celu weryfikacji wykonania zadania w raporcie zamieść katalog `/etc/kubernetes` oraz plik `/var/lib/kubelet/config.yaml`.

Za wszelkie aktywności nadobowiązkowe (przykładowo: przeprowadzenie testów manualnych wypunktowanych przez `kube-bench`) przewidziane są dodatkowe punkty :).

---

# Zadanie 2 - bezpieczne wdrażanie podów

## Pomoc
Zanim zaczniemy, gdyby były jakieś problemy można śmiało do mnie pisać: `Jan Kornacki` na FB, mail: `s180424@student.pg.edu.pl`.

## Motywacja
Wyobraź sobie, że brat (wiedząc, że znasz się trochę na rozwiązaniach chmurowych) zaczepił Cię na świątecznym spotkaniu i opowiedział swój genialny pomysł na nowy portal społecznościowy. Zapytał, czy byłbyś w stanie stworzyć dla niego jakieś środowisko deweloperskie, na którym koledzy programiści mogliby zbudować dany portal. Mimo iż nie wierzysz za bardzo w sens projektu, to nie jesteś zbyt asertywny i zgadzasz się pomóc - w końcu to rodzina. Lubisz tę osobę, więc chcesz zrobić to dobrze, a po kursie *Bezpieczeństwo i niezawodność systemów chmurowych* wiesz już na czym się skupić, żeby pierwszy lepszy programista nie zrobił czegoś czego będzie się potem żałowało.   

## Realizacja
Masz pomysł, żeby oprzeć się na Kubernetesie. To co masz zrobić to stworzyć prosty serwer www z gotowymi polami logowania. Dalszym rozwojem zajmą się programiści. Na szczęście masz już gotową i skonfigurowaną maszynę z poprzedniego genialnego projektu członka rodziny, tak więc zostało tylko:
1. znaleźć jakiś odpowiadający obraz kontenera,
2. stworzyć wolumin (PersistentVolume), w którym będą zapisane loginy i hasła (w formie jawnej do celów deweloperskich),
3. stworzyć odpowiedni prośbę o wolumin (PersistentVolumeClaim)
4. zebrać wszystko do pliku konfigurującego pod'a,
5. uruchomić i przetestować.

### Obraz kontenera
Podczas przeszukiwania Docker Hub w oko wpadł Ci obraz `simple-app:latest` użytkownika `jankejc`. Z opisu wynika, że całkowicie odpowiadać będzie Twoim potrzebom.

### Loginy i hasła - PersistentVolume
1. Tak jak ostatnio (poprzednie zadanie) łączysz się z swoją maszyną wirtualną (Debian/VirtualBox) po ssh.

2. W obecnym folderze tworzysz folder `genius-project-AAAAAA`, gdzie `AAAAAA` to Twój numer indeksu PG (taki masz rytuał). Np. `mkdir genius-project-AAAAAA`.

3. Następnie wchodzisz do tego folderu i tworzysz jeszcze jeden podfolder który udostępnisz pod'owi, w którym będzie plik z loginami i hasłami do portalu. 
```bash
cd genius-project-AAAAAA
mkdir shared
```

4. Następnie wchodzisz do tego folderu i tworzysz powyższy plik. UWAGA! Obraz `simple-app` wymaga, aby plik nazywał się `credentials.txt`. Ustawiasz uprawnienia tak, aby plik mógł być odczytany (choćby przez aplikację), ale nie nadpisany przez nikogo oprócz root'a. Brat chce mieć ścisłą kontrolę nad kontami tworzonymi w ramach portalu. Dodajesz również dwóch użytkowników, dzięki którym będziesz mógł testować działanie aplikacji.
```bash
cd shared
touch credentials.txt
chmod 744 credentials.txt
echo "brat, ilovecats" > credentials.txt
echo "dev, kti" >> credentials.txt
```

5. W folderze `genius-project-AAAAAA` tworzysz plik, który będzie służył jako plik konfigurujący `PersistentVolume`. 
```bash
cd ..
touch credentials-pv.yaml
```
   
6. Otwierasz ten plik ulubionym edytorem i konfigurujesz go tak, aby odnosił się do podfolderu do udostępnienia. Np. `nano credentials-pv.yaml`. Przykładową konfigurację podyktował Ci chat. Po dostosowaniu jej do Twoich potrzeb, powinna wyglądać mniej więcej tak:
```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: credentials-pv
spec:
  capacity:
    storage: 1Mi
  accessModes:
    - ReadWriteOnce
  hostPath:
    path: /root/genius-project-AAAAAA/shared
    type: Directory
```
### PersistentVolumeClaim
1. Potrzebujesz również `PersistentVolumeClaim`. Np. `touch credentials-pvc.yaml`.

2. Konfiguracja powinna wyglądać następująco: 
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: credentials-pvc
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Mi
```
*Aby zapisać plik w `nano` wystarczy naciśnąć Ctrl+X, a potem Y.*


### Konfiguracja pod'a
Na koniec tworzysz plik konfiguracyjny pod'a (np. `touch simple-app-pod.yaml`). A następnie odpowiednio go modyfikujesz:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: simple-app-pod
  labels:
    app: simple-app
spec:
  containers:
  - name: simple-app
    image: jankejc/simple-app:latest # znaleziony wcześniej obraz
    volumeMounts:
    - name: credentials-volume
      mountPath: /data               # UWAGA! simple-app wymaga, aby plik uwierzytelniający był w tym folderze 
    ports:
    - containerPort: 8080            # dzięki temu będziesz mógł przetestować swój prosty serwer www
  volumes:
  - name: credentials-volume
    persistentVolumeClaim:
      claimName: credentials-pvc     # nazwa stworzonego wcześniej pvc
```

### Uruchomienie
1. Aby móc przetestować serwer tworzysz jeszcze serwis `NodePort`, który będzie udostępniał ruch poza klaster.
```bash
touch simple-app-service.yaml
nano simple-app-service.yaml
```
```yaml
apiVersion: v1
kind: Service
metadata:
  name: simple-app-service
spec:
  type: NodePort
  ports:
    - port: 8080        # port simple-app
      targetPort: 8080
      nodePort: 30100   # port na węźle kubernetes
  selector:
    app: simple-app
```

2. W tym momencie, gdybyś miał maszynę wirtualną z dostępem do GUI to mógłbyś łatwo testować swój serwer w przeglądarce na porcie `30100`. Niestety masz Debiana CLI. Jest na to sposób. Wyłączasz swoją maszynę wirtualną (np. `sudo shutdown now`). Gdy maszyna się całkowicie wyłączy wchodzisz w jej ustawienia w VirtualBox'ie. Tam wchodzisz w Network/Adapter z NAT'em/Advanced/Port Forwarding i dodajesz nowy wpis z konkretnymi wartościami w odpowiednich polach:
- name: www,
- protocol: TCP,
- Host IP: (zostaje puste),
- Host Port: 8080,
- Guest IP: (zostaje puste),
- Guest Port: 30100.

Dzięki temu możesz testować swoją aplikację na urządzeniu w przeglądarce urządzenia, na którym uruchomiona jest maszyna wirtualna.

3. Wszystko powinno być gotowe, więc włączasz maszynę wirtualną, logujesz się do niej po ssh.

4. Przypomniałeś sobie, że domyślnie nie można uruchamiać podów na tym samym nodzie, na którym jest control plane. To ograniczenie - `taint` - można znieść jednorazowo następującym poleceniem:  
```bash
kubectl taint node debian node-role.kubernetes.io/control-plane=:NoSchedule-
```

> **SCREEN 1**
> 
> W folderze `genius-project-AAAAAA` wykonaj polecenie `ls` i zrób zrzut ekranu tak, aby widoczna była lista utworzonych wcześniej plików w aktualnym folderze. Niech screen nazywa się `genialny_projekt_1.png`

5. Z folderu `genius-project-AAAAAA` uruchamiasz serwis, przygotowujesz `PersistentVolume` i `PersistentVolumeClaim`. Na koniec uruchamiasz również samą aplikację.
```bash
kubectl apply -f simple-app-service.yaml
kubectl apply -f credentials-pv.yaml
kubectl apply -f credentials-pvc.yaml
kubectl apply -f simple-app-pod.yaml
```

6. Aby upewnić się, że wszystko zostało uruchomione wykonujesz serię komend.
```bash
kubectl get pods -A
kubectl logs [NAZWA_PODU]
kubectl get services
kubectl get pv
kubectl get pvc
```
UWAGA! `kubectl get pods -A` powinno być sprawdzane dopóki pod nie będzie `Running`.

> **SCREEN 2**
> 
> Zrób zrzut ekranu tak, aby widoczne były wyniki wywołanych komend. Nazwij go `genialny_projekt_2.png`. Jeśli nie zmieści się na jednym zrzucie, to proszę nazywać je np. `genialny_projekt_2_1.png`,  `genialny_projekt_2_2.png`.

7. Na maszynie, na której jest uruchomiona maszyna wirtualna wchodzisz w przeglądarkę i wpisujesz `localhost:8080`. Oczom ukazuje Ci się przepiękna strona, na której testujesz możliwość logowania. Logujesz się tak, jak gdybyś był deweloperem -> `login: dev`, `pass: kti`. Pojawia się komunikat powitalny z wyszczególnioną nazwą użytkownika.

> **SCREEN 3**
> 
> Zrób zrzut ekranu tak, który ukazuje powyższy widok. Nazwij go `genialny_projekt_3.png`.

## Sprawdzenie bezpieczeństwa
Przed oddaniem decydujesz się jeszcze na sprawdzenie czy Twoja konfiguracja pod'a została przeprowadzona zgodnie ze sztuką. W tym celu używasz jednego z wielu narzędzi do skanowania zasobów jakim jest np. `Polaris` (choć inne pewnie też by się sprawdziły). W tym celu:
1. pobierasz narzędzie,
2. skanujesz pod'a,
3. sprawdzasz w logach czy nie ma nic niepokojącego i...
4. cieszysz się, że nie oddałeś środowiska za szybko...

### Pobranie narzędzia
Polaris ma też wersję graficzną, ale jako, że korzystając z CLI czujesz się bardziej profesjonalnie, to zadowalasz się wersją tekstową. Pobierasz program na maszynie wirtualnej.
```bash 
wget https://github.com/FairwindsOps/polaris/releases/download/9.6.0/polaris_linux_amd64.tar.gz
```

### Skanowanie poda
1. Wykorzystujesz Polarisa do przeskanowania naszego poda. Poniższą komendę wykonujesz w folderze `genius-project-AAAAAA`.
```bash
polaris audit --audit-path simple-app-pod.yaml
```

2. Obserwujesz zdecydowanie za dużo tekstu, żeby go łatwo przyswoić, ale się nie poddajesz. Chat podpowiada Ci, że istnieje parser `jq`, który może trochę pomóc w odczycie. Instalujesz go.
```bash
sudo apt-get install jq
```

3. W tym momencie interesują Cię tylko wiadomości związane z bezpieczeństwem (`Security`). Po chwili siłowania się z chatem dostajesz to czego chcesz.
```bash
polaris audit --audit-path simple-app-pod.yaml | jq '.Results[].PodResult.ContainerResults[].Results | with_entries(select(.value.Success == false and .value.Category == "Security"))'
```

> **SCREEN 4**
> 
> Zrób zrzut ekranu, który ukazuje wynik powyższego polecenia. Nazwij go `genialny_projekt_4.png`.

### Podatność (`root login`)
1. No i wyszło szydło z worka... `runAsNonRoot -> false` oznacza, że nawet jeśli wcześniej ustawiłeś wartości uprawnień na `744` to prawdopodobnie zwykły użytkownik będzie miał możliwość nadpisania pliku, ponieważ kontener w danym podzie uruchamia się z uprawnieniami `root'a`.

2. Wcielając się w nieuczciwego programistę postanawiasz sprawdzić powyższą podatność. Wchodzisz na pod'a:
```bash
kubectl exec -it simple-app-pod -- /bin/sh
```

3. Próbujesz nadpisać plik z hasłami, który znajduje się w zamontowanym folderze `/data`. UWAGA! Należy podać komendę dokładnie jak poniżej, ponieważ środowisko jest dość wrażliwe i nie aż tak responsywne (choćby brak dopełnień tabulatorem).
```bash
nano /data/credentials.txt
```

4. Następnie próbujesz dopisać coś do pliku oraz zapisać (`AAAAAA` to numer indeksu).
```bash
...
AAAAAA, vuln
```

5. Wyświetlasz plik i okazuje się, że dopisanie przebiegło pomyślnie, to źle...
```bash
cat /data/credentials.txt
```

> **SCREEN 5**
> 
> Zrób zrzut ekranu, który ukazuje wynik powyższego polecenia. Nazwij go `genialny_projekt_5.png`.

6. Żeby uratować sytuację zmieniasz konfigurację poda dodając odpowiedni wpis, który uruchamia kontener jako zwykły użytkownik. Edytujesz plik `simple-app-pod.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: simple-app-pod
  labels:
    app: simple-app
spec:
  containers:
  - name: simple-app
    image: jankejc/simple-app:latest 
    volumeMounts:
    - name: credentials-volume
      mountPath: /data               
    ports:
    - containerPort: 8080    
    securityContext:      # dodatkowe linijki
      runAsNonRoot: yes   #
      runAsUser: 1001     #  
  volumes:
  - name: credentials-volume
    persistentVolumeClaim:
      claimName: credentials-pvc     
```

7. Skanujesz Polarisem, aby sprawdzić czy to rozwiązuje problem:
```bash
polaris audit --audit-path simple-app-pod.yaml | jq '.Results[].PodResult.ContainerResults[].Results | with_entries(select(.value.Success == false and .value.Category == "Security"))'
```

8. Nie ma już komunikatu o powyższej podatności, więc wprowadzasz zmiany i czekasz aż pod będzie `Running`:
```bash
kubectl delete pod simple-app-pod
kubectl apply -f simple-app-pod.yaml
kubectl get pods -A
```

9. Ponownie wchodzisz na pod'a i upewniasz się, że nie możesz nic dopisać do pliku.
```bash
kubectl exec -it simple-app-pod -- /bin/sh
nano /data/credentials.txt
```

10.  Super, nie da się, ale co w takim momencie robi każdy przeciętny użytkownik linuxa? Próbuje z `sudo`... (hasło to `yourpassword`).
```bash
sudo nano credentials.txt 
```

11.  Jak widać niestety dalej jest sposób na zmianę w pliku...

### Podatność podniesienie uprawnień
1. Skanując jeszcze raz pod'a Polaris'em:
```bash
polaris audit --audit-path simple-app-pod.yaml | jq '.Results[].PodResult.ContainerResults[].Results | with_entries(select(.value.Success == false and .value.Category == "Security"))'
```
  
2. Zauważasz, że widnieje tam komunikat o `privilegeEscalationAllowed`... To sprawia, że użytkownik może podnieść swoje uprawnienia... Aktualizujesz konfigurację poda `simple-app-pod.yaml`:
```bash
apiVersion: v1
kind: Pod
metadata:
  name: simple-app-pod
  labels:
    app: simple-app
spec:
  containers:
  - name: simple-app
    image: jankejc/simple-app:latest 
    volumeMounts:
    - name: credentials-volume
      mountPath: /data               
    ports:
    - containerPort: 8080    
    securityContext:      
      runAsNonRoot: yes  
      runAsUser: 1001     
      allowPrivilegeEscalation: false # dodatkowa linijka 
  volumes:
  - name: credentials-volume
    persistentVolumeClaim:
      claimName: credentials-pvc 
```

3. Ponownie skanujesz konfigurację pod'a, aby sprawdzić czy problem jest rozwiązany:
```bash
polaris audit --audit-path simple-app-pod.yaml | jq '.Results[].PodResult.ContainerResults[].Results | with_entries(select(.value.Success == false and .value.Category == "Security"))'
```

> **SCREEN 6**
> 
> Zrób zrzut ekranu, który ukazuje wynik powyższego polecenia. Nazwij go `genialny_projekt_6.png`.


4. Wygląda na to, że podatność została załatana, więc ponawiasz próbę nadpisania pliku bez `sudo` i z nim.
```bash
kubectl exec -it simple-app-pod -- /bin/sh
nano /data/credentials.txt
sudo nano /data/credentials.txt
```

5. O ile wejść do pliku można, tak nie jest on możliwy do nadpisania, a jeśli próbujesz skorzystać z `sudo` to dostajesz komunikat, że nie możesz tego zrobić. Nareszcie!

> **SCREEN 7**
> 
> Zrób zrzut ekranu, który ukazuje wynik polecenia z `sudo`. Nazwij go `genialny_projekt_7.png`.


## Podsumowanie
W końcu jesteś w stanie oddać bratu środowisko do wstępnych prac. Co prawda było jeszcze kilka ostrzeżeń w kontekście bezpieczeństwa i nie tylko, ale to na razie starczy, resztą zajmiesz się kiedy indziej. Ostatecznie projekt nie okazał się całkowitą stratą czasu, bo nauczyłeś się przynajmniej jak dobrze wdrażać pod'y i na co zwracać uwagę w przyszłości. Szczególnie jeśli jest tak dużo narzędzi, które mogą Ci w tym pomóc...  


## Przybornik
Usunięcie serwisu
```bash
kubectl delete service [NAZWA_SERWISU]
```

Restart całego środowiska, gdyby były jakieś problemy z niestawiającymi się pod'ami.
```bash
systemctl restart kubelet
```

Usunięcie PersistentVolume
```bash
kubectl delete pv [NAZWA_PV]
```

Usunięcie PersistentVolumeClaim
```bash
kubectl delete pvc [NAZWA_PVC]
```

Dostęp na pod'a
```bash
kubectl exec -it simple-app-pod -- /bin/sh
```

Usunięcie pod'a
```bash
kubectl delete pod [NAZWA_PODA]
```

Wdrożenie
```bash
kubectl apply -f [NAZWA]
```

Podejrzenie wszystkich pod'ów
```bash
kubectl get pods -A
```

---

# Zadanie 3 - izolacja sieci w systemie Kubernetes
Zadanie polega na odizolowaniu odpowiednich komponentów systemu Kubernetes na poziomie sieciowym z wykorzystaniem Network Policies.
Zadanie podzielone zostało na następujące fazy:
1. Wcielisz się w rolę developera i wykonasz deployment swojej prostej aplikacji webowej wraz z bazą danych. 
2. Wcielisz się w rolę atakującego i wykorzystasz domyślny brak izolacji podów w systemie Kubernetes wykonując atak na bazę danych, która została stworzona w ramach pierwszej fazy.
3. Wcielisz się w rolę administratora systemu Kubernetes i z wykorzystaniem odpowiednich narzędzi wykryjesz brak odpowiedniej izolacji sieci.
4. Wciąż jako administrator wprowadzisz odpowiednią izolację sieci z wykorzystaniem Network Policies.
5. Ponownie wcielisz się w rolę atakującego, aby powtórzyć atak.
6. Powrócisz do roli administratora aby wykryć, z wykorzystaniem odpowiedniego narzędzia, brak domyślnej polityki odrzucającej w ramach namespace. Wprowadzisz taką politykę.

## 1. Deployment aplikacji webowej oraz bazy danych

W ramach tej części zadania wcielamy się w rolę developera, który chce wykonać deployment swojej aplikacji webowej wykorzystującą bazę danych.

### 1. Tworzenie namespace
W pierwszej kolejności musimy stworzyć namespace w ramach którego będziemy wdrażać swoje zasoby.
Tworzymy plik o nazwie task-3-namespace.yaml z następującą zawartością:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: task-3-namespace
  labels:
    networking/namespace: task-3-namespace
```
Zasób tworzymy poprzez wykonanie komendy
`kubectl apply -f task-3-namespace.yaml`

### 2. Wdrażanie bazy danych
Następnie wdrażamy odpowiedniego poda z naszą bazą danych. Tworzymy plik database-pod.yaml z następującą zawartością:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: database-pod
  namespace: task-3-namespace
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
  namespace: task-3-namespace
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
  namespace: task-3-namespace
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
  namespace: task-3-namespace
spec:
  type: NodePort
  ports:
  - nodePort: 30001
    port: 3000
    targetPort: 3000
  selector:
    app: web-app-pod
```

Teraz należy wykonać także port forwarding na maszynie wirtualnej, podobnie jak robiliśmy to w ramach zadania drugiego. W pierwszej kolejności należy wyłączyć maszynę wirtualną.
Gdy maszyna się całkowicie wyłączy wchodzisz w jej ustawienia w VirtualBox'ie. Tam wchodzisz w Network/Adapter z NAT'em/Advanced/Port Forwarding i dodajesz nowy wpis z konkretnymi wartościami w odpowiednich polach:
- name: task3webapp,
- protocol: TCP,
- Host IP: (zostaje puste),
- Host Port: XX31, gdzie `XX` to dwie ostatnie cyfry naszego numeru indeksu
- Guest IP: (zostaje puste),
- Guest Port: 30001.

### 4. Logowanie

W przeglądarce wpisujemy adres `http://localhost:XX31`, gdzie `XX` to dwie ostatnie cyfry naszego numeru indeksu.
Naszym oczom ukazuje się ekran logowania do którego wprowadzamy wymyślone przez siebie dane.
Uwaga! Nie należy wprowadzać swoich prawdziwych loginów i haseł!
Po zalogowaniu powinniśmy uzyskać komunikat o pomyślnym zalogowaniu.
Wykonujemy zrzut ekranu i nazywamy go XXXXXX_zad3_1.jpg, gdzie XXXXXX to nasz numer indeksu. 

## 2. Atak na bazę danych

W ramach drugiego podzadania wcielimy się w rolę atakującego i wykonamy atak na uprzednio wdrożoną bazę danych.

### 1. Tworzenie środowiska ataku
Tworzymy plik attacker-pod.yaml o poniższej zawartości:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: task-3-namespace
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
Poprzez wykonanie komendy `kubectl get pods -o wide -n task-3-namespace` uzyskujemy adres IP poda z bazą danych. W rzeczywistym scenariuszu ataku adres ten moglibyśmy uzyskać np. poprzez skanowanie sieci.

### 3. Wykonanie ataku
Na poda pełniącego funkcję naszego środowiska do ataku dostajemy się z wykorzystaniem komendy `kubectl exec -it attacker-pod -n task-3-namespace -- /bin/sh`.
Po pomyślnym wejściu do poda mozna sprawdzić łączność z bazą danych poleceniem `ping <ADRES_IP_BAZY_DANYCH>`.
W celu połączenia z bazą danych wykonujemy komendę:
`psql -h <ADRES_IP_BAZY_DANYCH> -p 5432 -U <NAZWA_UŻYTKOWNIKA> -d database`
gdzie w `<ADRES_IP_BAZY_DANYCH>` wprowadzamy uzyskany adres IP poda bazy danych, zaś w polu `<NAZWA_UŻYTKOWNIKA>` oraz haśle wprowadzamy użyte wcześniej przy wdrażaniu sekretne wartości, które ze względu na prostotę nie byłyby zbyt skomplikowane do odgadnięcia dla rzeczywistego atakującego.

Po podłączeniu się do bazy wykonujemy komendę:
`SELECT * FROM users;`
Wykonujemy zrzut ekranu i nazywamy go XXXXXX_zad3_2.jpg, gdzie XXXXXX to nasz numer indeksu.
Po wykonaniu proszę wyjść z poda komendą exit a następnie usunąć go komendą `kubectl delete pod <NAZWA_PODA> -n <NAZWA_NAMESPACE>`.

## 3. Skan systemu

W tej części zadania wcielamy się w administratora systemu Kubernetes, który przeprowadzi skan celem wykrycia niewystarczającej izolacji sieci.

### 1. Pobranie narzędzi do skanowania sieci
W pierwszej kolejności należy pobrać narzędzie, które umożliwi nam wykrycie braku izolacji sieci na poziomie komunikacji między podami w systemie Kubernetes.

Dla przykładu może, ale nie musi, być to narzędzie Kubescape, które instalujemy za pomocą poniższej komendy. Komenda zainstaluje narzędzie oraz przeprowadzi ogólny skan:
`curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash`

### 2. Przeprowadzenie skanu pod kątem braku polityk sieciowych

W celu uzyskania dokładniejszych informacji odnośnie polityk sieciowych w naszym namespace z narzędziem Kubescape wykonujemy skan z opcjami jak poniżej:
`kubescape scan control C-0260 -v --include-namespaces task-3-namespace`

Niezależnie od wykorzystanego narzędzia proszę załączyć odpowiedni zrzut ekranu jako dowód wykrycia braku izolacji sieci w naszym namespace.
Proszę nazwać go XXXXXX_zad3_3.jpg, gdzie XXXXXX to nasz numer indeksu.

## 4. Wprowadzenie izolacji sieci

W ramach tego zadania, wciąż jako administrator systemu Kubernetes, wprowadzimy odpowiednią izolację sieci zgodnie z uwagami uzyskanymi od narzędzi skanujących.

### 1. Zastosowanie izolacji dla bazy danych
Tworzymy network policy dla bazy danych z wykorzystaniem poniższego pliku database-network-policy.yaml, izolując całkowicie ruch wyjściowy a ruch wejściowy ograniczając do aplikacji webowej.
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: database-network-policy
  namespace: task-3-namespace
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
            networking/namespace: task-3-namespace
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
  namespace: task-3-namespace
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
            networking/namespace: task-3-namespace
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
Proszę powtórzyć skan (z punktu 3.2) a zrzut ekranu wynikowego skanu nazwać XXXXXX_zad3_4.jpg, gdzie XXXXXX to nasz numer indeksu.

## 5. Powtórny atak na bazę danych

W tej fazie zadania powracamy do roli atakującego i ponownie próbujemy wykonać atak na bazę danych.
Proszę wykonać kroki analogiczne do punktu 2.
Czy atak się powiódł? Dlaczego otrzymaliśmy taki rezultat? Proszę odpowiedzieć w 1-2 zdaniach i swoje wnioski spisać w pliku XXXXXX_zad3_wnioski.txt, gdzie XXXXXX to nasz numer indeksu.

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
Dla narzędzie kubeaudit, przy założeniu, że definicja naszego namespace znajduje się w pliku `task-3-namespace.yaml`, jest to następująca komenda:
`kubeaudit netpols -f task-3-namespace.yaml`.

Proszę wykonać zrzut ekranu prezentujący wynik takiego skanowania i nazwać go XXXXXX_zad3_6.jpg, gdzie XXXXXX to nasz numer indeksu.

### 2. Zastosowanie domyślnej polityki sieciowej dla namespace
Proszę zmodyfikować zawartość pliku `task-3-namespace.yaml` na tę widoczną ponizej:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: task-3-namespace
  labels:
    networking/namespace: task-3-namespace

---

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: task-3-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```
oraz zastosować komendą `kubectl apply -f`

### 3. Powtórny skan
Proszę ponownie wykonać skan naszego namespace pod kątem braku domyślnej polityki `deny`, analogicznie jak w punkcie 6.1.
Proszę wykonać zrzut ekranu prezentujący wynik takiego skanowania i nazwać go XXXXXX_zad3_7.jpg, gdzie XXXXXX to nasz numer indeksu.

# Autorzy
https://github.com/Wojciech-Baranowski
https://github.com/jankejc
https://github.com/Karakean
https://github.com/jhgrzybowski
