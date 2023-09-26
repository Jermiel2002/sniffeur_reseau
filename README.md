# SNIFFER RESEAU

![Image drôle](https://cdn.funinformatique.com/wp-content/uploads/2012/01/17174819/sniffing-reseau.jpg)

-----------------

* Description

  > _Ici on va développer un programme qui capture tous les     paquets   circulant dans le réseau et nous permettant d'en modifier le   contenu._  
   Il peut intercepter toutes les informations envoyées sur un   réseau local et ainsi récupérer à la fois l'identité des   utilisateurs et leurs mots de passe envoyés par un service qui   dispose de données non chiffrées comme Telnet, DNS, SMTP, FTP et   HTTP* 

* Comment fonctionne un sniffer ? 

  > Le but du *sniffer* n'est pas d'infecter le système avec d'autres menaces.  Il ne peut pas non plus causer de problèmes de performances ou d'instabilité du système, ni constitué une menace  sérieuse pour les données de votre ordinateur.  Cependant, une version malveillante d'un sniffer peut effectuer des actions qui causent de sérieux problèmes de confidentialité.
  > Ce programme ne nécessite pas de ressources système et ne dispose pas d'une interface utilisateur graphique, il peut donc être très difficile à détecter lorsqu'il se connecte à votre ordinateur.
  > Une fois à l'intérieur, il peut être utilisé par des pirates pour voler les données sensibles d'un particulier ou d'une entreprise.
  > Cela peut prendre des mois, voire des années, avant de détecter un renifleur malveillant.  Le pirate peut récupérer des mots de passe, des coordonnées, voire des numéros de carte de crédit de sa victime.

    * En bref !

      > Vérifier l'utilisation du réseau de l'utilisateur et filtrer certains paquets.
      > Capturer tous les paquets réseau envoyés d'un endroit à un autre du réseau.
      > Enregistrer les données des paquets capturés dans un fichier
      > Analyser les données enregistrées pour trouver des informations de connexion, des mots de passe, des numéros de carte de crédit, des id ou d'autres infos utils (du pishing)

* Comment un sniffer peut-il pénétrer dans un réseau ?

  > Une grande partie des protocoles internet transmettent encore des informations non chiffrées. Ainsi, lorsqu'un utilisateur du réseau ouvre son courrier électronique via un protocole POP ou IMAP ou ouvre un site wev qui commence par HTTP, toutes les infos envoyées ou reçues peuvent être interceptées.
  > Lorsqu'un utilisateur se connecte à un serveur de messagerie utilisant le protocole POP3 par exemple, pour consulter son courrier électronique, le pirate récupère le login/mot de passe grâce au reniffleur.
  > Les reniffleurs malveillants sont souvent installés par d'autres logiciels malveillants tels que des virus, des chevaux de Troie ou des protes dérobées.

* Comment se protéger ?

  > La meilleure protection est l'utilisation de protocoles de communication chiffrés tels que SSH (SFTP, scp), SSL (HTTPS, FTPS) et l'utilisation de protocole d'authentifications tels que SSO pour accéder aux applications et services de son entreprise.

-----------------

* INFOS
  > Ce projet permet de consolider ses connaissances en réseau et spécifiquement en modèle OSI.
  > Il est l'ai utilisé que sous linux
  > Ce projet est divisé en plusieurs fichiers sources traitant des couches OSI différentes : transport, réseau, liaison de données,...

-----------------

* INSTALLATION NECESSAIRE
  > Il est nécessaire d'installer les bibliothèques pcap : `sudo apt install libpcap-dev`

-----------------

* UTILISATION
  > Pour le lancer, se mettre dans le bon dossier
  > Entrer dans le terminal : `make`
  > `sudo ./sniffer [-i <interface> -o <fichier> -f <filtre BPF>]`
* EXEMPLES
  > sudo ./sniffer // mode par défaut
  > sudo ./sniffer -i lo // choisit l'interface loopback pour la capture
  > sudo ./sniffer -f "tcp and dst port 80" // filtre le trafic pour HTTP uniquement
  > sudo ./sniffer -o monfichier.pcap // utilise un fichier .pcap à la place

-----------------

* PISTE D'AMELIORATION
  > Prendre en compte plus de protocoles
  > ajouter une option pour exporter les résultats dans un fichier
  > ajouter des fonctionnalités
  > tenter de le porter sur une interface graphique (avancé)
  > recopier dans un autre langage de programmation