
# Informations générales

Ce script permet d'automatiser au maximum la réalisation de la machine overflow de la plateforme Hack The Box (HTB).  
Il essaye de rester le plus fidèle possible au déroulement 'humain' (récupération des informations de façon essentiellement dynamique).


# Prérequis

Ce script a été réalisé en python3 version 3.8.10

**Installation des dépendances :**

- Python

```bash
python3 -m pip install -r requirements.txt
```

**Les dépendances ci-dessous ne sont à installer que si les outils ne sont pas présents sur la machine (elles ne sont donc pas forcément à faire)**

- padBuster

```bash
sudo apt-get install libcrypt-ssleay-perl
wget https://raw.githubusercontent.com/AonCyberLabs/PadBuster/master/padBuster.pl
```

- SQLmap

```bash
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
```

- rockyou.txt

```bash
wget https://gitlab.com/kalilinux/packages/wordlists/blob/kali/master/rockyou.txt.gz
```


**Configuration :**

- Configurer le /etc/hosts pour résoudre les domaines : overflow.htb, devbuild-job.overflow.htb
- Créer un lien symbolique dans libs/ pour lancer padBuster.pl
- Créer un lien symbolique dans wordlist/ avec le dictionnaire rockyou.txt
- Vérifier que sqlmap est dans le PATH pour pouvoir exécuter 'sqlmap' directement
- Dans le fichier settings.py, il est possible de renseigner l'IP de sa machine qui communique avec le site HTB

# Utilisation

Il faut tout simplement lancer le main en sudo.
Sudo est obligatoire car on est obligé de lancer un serveur local en Python sur le port 80 (conditions imposées par l'épreuve)

```bash
sudo python3 main.py
```


# Limites rencontrées pour l'implémentation de l'automatisation


1. L'interface de http://overflow.htb/admin_cms_panel/ gère ses cookies de sessions avec du Javascript et ne peut donc pas être géré avec des requêtes GET/POST standard.  
Par manque de temps, cette partie a donc été laissée de côté.  
A noter que se connecter sur cette interface permet seulement de récupérer le domaine suivant : http://devbuild-job.overflow.htb/

2. Le payload final doit être exécuté avec un pipe géré par cat.  
Ce qui a pour effet de bord de casser le tunnel ouvert par mon code python.  
Il y a sûrement un moyen de pallier au problème mais je n'ai pas réussi à trouver dans les temps.  
Il faudra donc exécuter 2 commandes manuelles que le script vous fournira.