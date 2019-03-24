This is a draft for something that could be the base of a build and integration test stage. Example manual usage, building dhcpoptinj and then testing it:

1. Create the docker image needed for the build/test. You may also just use whatever image you'd like, as long as you can install the build and test dependencies as listed in the Dockerfile run script.
   ```bash
   docker build -t dhcpoptinj-stretch . 
   ```
1. Assuming `$PWD` is the dhcpoptinj source directory:
   ```bash
   docker container run -ti -v $PWD:/src:ro --cap-add=NET_ADMIN dhcpoptinj-stretch bash -c 'mkdir /build && cd /build && cmake /src && make && make install && test-dhcpoptinj'
	```

The same image can also be used for debugging, in which case a few more options is handy to make gdb and the like work:
```bash
docker container run -ti -v $PWD:/src:ro --cap-add=NET_ADMIN --cap-add=SYS_PTRACE --security-opt seccomp=unconfined dhcpoptinj-stretch
```
