#!/bin/bash

##                                /T /I          
##                               / |/ | .-~/    
##                           T\ Y  I  |/  /  _  
##          /T               | \I  |  I  Y.-~/  
##         I l   /I       T\ |  |  l  |  T  /   
##  __  | \l   \l  \I l __l  l   \   `  _. |    
##  \ ~-l  `\   `\  \  \\ ~\  \   `. .-~   |    
##   \   ~-. "-.  `  \  ^._ ^. "-.  /  \   |    
## .--~-._  ~-  `  _  ~-_.-"-." ._ /._ ." ./    
##  >--.  ~-.   ._  ~>-"    "\\   7   7   ]     
## ^.___~"--._    ~-{  .-~ .  `\ Y . /    |     
##  <__ ~"-.  ~       /_/   \   \I  Y   : |
##    ^-.__           ~(_/   \   >._:   | l______     
##        ^--.,___.-~"  /_/   !  `-.~"--l_ /     ~"-.  
##               (_/ .  ~(   /'     "~"--,Y   -=b-. _) 
##                (_/ .  \  :           / l      c"~o \
##                 \ /    `.    .     .^   \_.-~"~--.  ) 
##                  (_/ .   `  /     /       !       )/  
##                   / / _.   '.   .':      /        ' 
##                   ~(_/ .   /    _  `  .-<_      -Row
##                     /_/ . ' .-~" `.  / \  \          ,z=.
##                     ~( /   '  :   | K   "-.~-.______//
##                       "-,.    l   I/ \_    __{--->._(==.
##                        //(     \  <    ~"~"     //
##                       /' /\     \  \     ,v=.  ((
##                     .^. / /\     "  }__ //===-  `
##                    / / ' '  "-.,__ {---(==-
##                  .^ '       :  T  ~"   ll
##                 / .  .  . : | :!        \\ 
##                (_/  /   | | j-"          ~^
##                  ~-<_(_.^-~"               

echo
echo Before attempting install, please copy your SSH key to the target system
echo

echo "############## ByFire Installation ###################"
echo Obtaining additional package....
git clone --depth 1 -b v3.0.5 https://github.com/ColorlibHQ/AdminLTE adminlte
rsync -a ./adminlte/plugins packages/byfire/static/
rsync -a ./adminlte/dist packages/byfire/static/
echo
echo -n "IP of target firewall: "
read FWIP
echo [byfire] > hosts
echo ${FWIP} >> hosts
echo

echo -n "Enter user for target firewall: "
read FWUSER
echo

echo Configuring...
ansible-playbook -i hosts endow.yaml --user ${FWUSER} --ask-become-pass

rm hosts
