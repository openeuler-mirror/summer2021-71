sudo -E make -j 2
sudo -E make install
sudo cp -f src/isula /usr/bin/
sudo cp -f src/isulad /usr/bin/
sudo cp -f src/isulad-shim /usr/bin/
sudo cp -f src/libisula.so /usr/lib64
sudo cp -f src/daemon/modules/image/libisulad_img.so /usr/lib64
sudo cp -f ./daemon.json /etc/isulad/
sudo systemctl restart isulad

