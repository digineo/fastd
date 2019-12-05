# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.synced_folder '.', '/app', type: 'rsync'

  config.vm.define :freebsd do |machine|
    machine.vm.guest = :freebsd
    machine.vm.box = "freebsd/FreeBSD-12.1-RELEASE"

    machine.ssh.shell = "sh"

    config.vm.provider "virtualbox" do |vb|
      vb.memory = "4096"
      vb.cpus = "2"
    end

    nic = `ip -o -4 route show to default`.match(/dev (\S+) /)
    config.vm.network "public_network", bridge: $1

    config.vm.provision "shell", inline: <<-SHELL
      pkg install --quiet --yes python go git pkgconf

      svnlite checkout https://svn.freebsd.org/base/release/12.1.0 /usr/src
    SHELL
  end
end

