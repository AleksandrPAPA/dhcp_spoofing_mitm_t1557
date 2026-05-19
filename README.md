## Эксперимент: защита от DHCP Spoofing (MITRE ATT&CK T1557.003)

**Авторы:** Левашов А.В., Капаев С.Д.
**Группа:** КА-25-06  
**ВУЗ:** РГУ нефти и газа (НИУ) имени И.М. Губкина  
**Год:** 2026

---

## Описание работы

В данном репозитории представлены материалы эксперимента по реализации и анализу эффективности защиты от атаки Adversary-in-the-Middle: DHCP Spoofing (MITRE ATT&CK T1557.003) на уровне коммутаторов трёх вендоров:

- Cisco 2960
- Eltex MES1428
- MikroTik RouterOS

---

## Структура репозитория:
```

/
├── README.md                          # Инструкция по развёртыванию
├── attack_results_raw.csv             # Сырые результаты 30 запусков атаки
├── dhcp_spoofing_attack.py            # Скрипт атаки (Python + Scapy)
├── configs/
│   ├── cisco_dhcp_snooping.txt        # Конфиг для Cisco 2960
│   ├── eltex_dhcp_snooping.txt        # Конфиг для Eltex MES1428
│   └── mikrotik_dhcp_filter.rsc       # Конфиг для MikroTik RouterOS
├── graphs/
│   ├── graph_boxplot.png              # Распределение времени обнаружения
│   ├── graph_cpu.png                  # Нагрузка на CPU
│   ├── graph_detection_time.png       # Время обнаружения
│   ├── graph_efficiency.png           # Эффективность защиты
│   ├── graph_latency.png              # Влияние на задержку
│   ├── graph_roc.png                  # ROC-кривые
│   └── graph_timeline.png             # Временная диаграмма атаки
└── docs/
└── topology.png                   # Топология тестового стенда

```

---

## Требования к оборудованию и ПО

| Компонент       |                              Требование                                 |
|-----------------|-------------------------------------------------------------------------|
| Коммутаторы     | Cisco 2960, Eltex MES1428, MikroTik (RouterOS 6.49+)                    |
| DHCP-сервер     | ALT Linux Server 10.1 / Ubuntu / Debian (isc-dhcp-server)               |
| Клиент (жертва) | ALT Linux / любой Linux с DHCP-клиентом                                 |
| Атакующий       | Kali Linux / любой Linux с Python 3 и Scapy                             |
| Сеть            | Подсеть 192.168.1.0/24, все устройства в одном широковещательном домене |

---

## Развёртывание тестового стенда

### 1. Настройка DHCP-сервера (ALT Linux)

```bash
# Назначение статического IP
mkdir -p /etc/net/ifaces/enp1s0
cat > /etc/net/ifaces/enp1s0/options <<EOF
TYPE=eth
DISABLED=no
BOOTPROTO=static
EOF
echo "192.168.1.2/24" > /etc/net/ifaces/enp1s0/ipv4address
systemctl restart network
```

```bash
# Установка DHCP-сервера
apt-get update && apt-get install -y dhcp-server

# Настройка dhcpd.conf
cat > /etc/dhcp/dhcpd.conf <<EOF
ddns-update-style none;
subnet 192.168.1.0 netmask 255.255.255.0 {
    option routers 192.168.1.1;
    option subnet-mask 255.255.255.0;
    option domain-name-servers 8.8.8.8;
    range 192.168.1.100 192.168.1.200;
    default-lease-time 21600;
    max-lease-time 43200;
}
EOF
```

```bash
# Запуск DHCP-сервера (название интерфейса может отличаться)
echo 'DHCPDARGS=enp1s0' > /etc/sysconfig/dhcpd
systemctl enable dhcpd
systemctl start dhcpd
```

### 2. Настройка клиента (ALT Linux)

```bash
# Настройка интерфейса на получение IP по DHCP
mkdir -p /etc/net/ifaces/eth0
cat > /etc/net/ifaces/eth0/options <<EOF
TYPE=eth
DISABLED=no
BOOTPROTO=dhcp
EOF
systemctl restart network
```

### 3. Включение защиты на коммутаторах

Cisco 2960
```bash
conf t
ip dhcp snooping
ip dhcp snooping vlan 1
no ip dhcp snooping information option
interface fastEthernet 0/1
 ip dhcp snooping trust
interface fastEthernet 0/2
 ip dhcp snooping limit rate 10
ip arp inspection vlan 1
interface range fastEthernet 0/1-2
 ip arp inspection trust
end
write memory
```

Eltex MES1428
```bash
configure
ip dhcp snooping
ip dhcp snooping vlan 1
interface fastethernet 1/1
 ip dhcp snooping trust
interface fastethernet 1/2
 ip dhcp snooping limit 10
ip arp inspection vlan 1
end
copy running-config startup-config
```

MikroTik CloudOS
```bash
/interface bridge set [find] dhcp-snooping=yes
/interface bridge port set [find where interface=ether2] dhcp-snooping=trusted
/interface bridge port set [find where interface=ether3] dhcp-snooping=no
/ip firewall filter add chain=input protocol=udp dst-port=67 in-interface=ether3 action=drop
/ip firewall filter add chain=input protocol=udp src-port=68 dst-port=67 action=accept
```

---

## Запуск атаки

#Установка зависимостей на атакующем (Kali Linux)
```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-scapy
```

#Скрипт атаки можно посмотреть в dhcp_spoofing_attack.py

#Запуск скрипта атаки
```bash
sudo apt arp-scan --local          #Поиск MAC-адреса жертвы
sudo python3 dhcp_spoofing_attack.py aa:bb:cc:dd:ee:ff        #Запуск атаки (замените MAC на реальный из предыдущей команды
```

---

Сбор метрик

```
Метрика Команда / способ
Время обнаружения / show ip dhcp snooping statistics (Cisco/Eltex) или /log print (MikroTik)
Задержка / ping -c 100 192.168.1.1 (с клиента)
Нагрузка / CPU show processes cpu history (Cisco) / show system cpu (Eltex) / /system resource print (MikroTik)
Процент блокировки / Из attack_results_raw.csv: 100 * (1 - mean(attack_success))
```

---

Результаты эксперимента

```
Вендор Эффективность Среднее время обнаружения Прирост CPU Прирост задержки
Cisco 2960 100% 412,50 мс +3.13% +11.9%
Eltex MES1428 100% 652,32 мс +5.11% +13.8%
MikroTik 80% 1885,38 мс +9.55% +21.7%
```

Графики результатов находятся в папке /graphs.

---

Воспроизводимость эксперимента

Для обеспечения воспроизводимости зафиксированы следующие контролируемые переменные:

```
Параметр Значение
Версия ОС DHCP-сервера ALT Linux Server 10.1
Версия ПО клиента ALT Linux Server 10.1
Версия Cisco IOS 15.0(2)
Версия Eltex 1.0.15
Версия MikroTik RouterOS 6.49
Количество итераций 10 запусков на сценарий
Фоновый трафик 100 Мбит/с (iperf3)
```

---

## Ссылки

- [MITRE ATT&CK T1557.003 — Adversary-in-the-Middle: DHCP Spoofing](https://attack.mitre.org/techniques/T1557/003/)
- [Cisco DHCP Snooping Configuration Guide (IOS 15.0)](https://www.cisco.com/en/US/docs/general/Test/dwerblo/broken_guide/snoodhcp.html)
- [Scapy — Packet manipulation tool (официальная документация)](https://scapy.readthedocs.io/)
- [MikroTik RouterOS — DHCP Snooping / Bridge Filter Documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/328068/Bridging+and+Switching)
- [ALT Linux Server — документация по настройке сети](https://www.altlinux.org/%D0%9D%D0%B0%D1%81%D1%82%D1%80%D0%BE%D0%B9%D0%BA%D0%B0_%D1%81%D0%B5%D1%82%D0%B8)
- [Eltex — руководство пользователя (DHCP Snooping)](https://docs.eltex-co.ru/pages/viewpage.action?pageId=98926668)

---

Лицензия

Материалы репозитория могут быть использованы в образовательных и научных целях с указанием авторства.

Авторы: Левашов А.В., Капаев С.Д.

Дата: 2026
