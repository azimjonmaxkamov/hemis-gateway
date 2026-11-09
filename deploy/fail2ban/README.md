# fail2ban integratsiyasi

Gateway har bir IP bloklashni `data/security.log` fayliga yozadi. fail2ban shu faylni kuzatib,
IP ni server firewall darajasida ham yopadi (so'rovlar nginx ga ham yetib kelmaydi).

```bash
sudo apt install fail2ban
sudo cp filter.d/hemis-gateway.conf /etc/fail2ban/filter.d/
sudo cp jail.d/hemis-gateway.conf   /etc/fail2ban/jail.d/
# jail.d/hemis-gateway.conf dagi logpath va ignoreip ni tekshiring
sudo systemctl restart fail2ban
sudo fail2ban-client status hemis-gateway        # bloklangan IP lar
sudo fail2ban-client set hemis-gateway unbanip 1.2.3.4   # qo'lda chiqarish
```

Panelda IP blokdan chiqarilganda gateway darhol ruxsat beradi, lekin firewall bloki o'z muddati tugaguncha
(yoki yuqoridagi `unbanip` buyrug'igacha) qoladi.
