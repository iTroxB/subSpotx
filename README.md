# **subSpotx**

![](/img/sub1.png)

Subdomains discovery tool developed in Go. You will need a Security Trails account to use its own API KEY.

## Install tool

- Download the repository

```shell
sudo rm -rf /usr/bin/subSpotx
sudo git -C /opt clone https://github.com/iTroxB/subSpotx.git
```

- Modify main.go file and enter Security Trails own API_KEY before compiling

```shell
sudo nano /opt/subSpotx/main.go 
```

![](/img/sub3.png)

- To use the system-level tool as an executable binary from a relative path, create a symbolic link to the /usr/bin directory from the repository directory.

```shell
sudo ln -s /opt/subSpotx/subSpotx /usr/bin/subSpotx
```

## Use tool

- subSpotx -h

![](/img/sub2.png)
