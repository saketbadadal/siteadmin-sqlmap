while true; do
echo "traping..."

trap "kill 0" SIGTSTP
done
