# cryptoKey

C code for a Teensy microcomputer connected to a USBKey could potentially be used to create an asymetrical key exchange thats only
accessible localy. 

This could make it extremely difficult for a tresspasser to undermine the integrity side of the security triad effectivley creating
an authenticated channel between two users.

The host application runs a series of tests on the device and its random number generator - 
A Second host application is being developed in C++ and will use the USBKey as a two factor version of netcat.
