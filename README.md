# KDC-based-key-establishment

This application was jointly developed by  Nipam and Narasimha(N&N). Client part of 
this application was implemented by Nipam while KDC part was implemented by Narasimha. 
Encryption algorithms which are used to encrypt communicating messages and to store 
client's master keys are jointly implemented
-----------------------------------------------------------------------------------
--------------------------------------Compilation----------------------------------

The KDC program can be compiled using the command
gcc -o kdc KDC.c -lcrypto
where as client program can be compiled using the command
gcc -o client client.c -lcrypto
------------------------------------------------------------------------------------
------------------------------------------Run---------------------------------------
After successful compilation, KDC program can be run by using the command
./kdc -p <port number> -o <output filename> -f <password filename>
If client is a sender, then client program should be run by using the command
./client -n <myname> -m <type> -o <other party name> -i <inputfile> -a <kdc ipaddress> -p <kdc port>
whereas if it is a receiver, it should be run using the command
./client -n <myname> -m <type> -s <outenc> -o <outflie> -a <kdc ipaddress> -p <kdc port>
-------------------------------------------------------------------------------------
To the best of developers knowledge, this code runs perfectly fine as long as the inputs
are give according to the format
