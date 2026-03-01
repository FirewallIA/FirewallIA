# Détache XDP de chaque interface
sudo ip link set ens37 xdp off
sudo ip link set ens38 xdp off

# Vérifie que c'est détaché
ip link show ens37 | grep xdp
ip link show ens38 | grep xdp
