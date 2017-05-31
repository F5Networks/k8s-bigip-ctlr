# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  if Vagrant.has_plugin?("vagrant-timezone")
    config.timezone.value = :host
  end
  config.vm.box = "ubuntu/wily64"
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "4096"
    vb.cpus = "4"
   end

  config.vm.provision "shell", privileged: false, inline: <<-SHELL
    set -x
    make -C /vagrant/ build-deps VAGRANT_INSTALL=1
  SHELL
end
