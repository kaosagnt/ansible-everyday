
alias cls tput clear
alias priv sudo
alias pico nano -w
alias pine alpine
alias md mkdir
alias rd rmdir
alias df	df -k
alias du	du -k

set prompt="%m:%~>"
set correct=cmd
set autolist=ambiguous

setenv PATH $PATH":/usr/sbin:/sbin:$HOME/bin"

umask 022
