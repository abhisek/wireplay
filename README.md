Wireplay
========

A minimalist approach to replay pcap dumped TCP sessions with modification as
required.

The aim of this project is to build an usable but simplistic tool which can help
in selecting the TCP session to replay. It can play both client as well as the
server during a replay session.

Obviously replay attacks doesn't work against protocols which are cryptographically
hardened or implements protocol specific replay preventation mechanism like
challenge/response etc. Wireplay implements a plugin/hook subsystem mainly for
the purpose of working around those replay prevention mechanism and also perform
a certain degree of fuzz testing.

It also won't work out of the box for certain non-deterministic sessions like
say:

* Original 

    C> GET /abc.tar.gz HTTP/1.1\r\n...
    S> HTTP 404 Not Found
    ...

* Replay

    C> GET /abc.tar.gz HTTP/1.1\r\n..
    S> HTTP 200 Found

Options
--------

user@linux$ ./wireplay
Wireplay - The TCP Replay Tool v0.2

    Options:
            -r       --role    [ROLE]       Specify the role to play (client/server)
            -F       --file    [FILE]       Specify the pcap dump file to read packets
            -t       --target  [TARGET]     Specify the target IP to connect to when in client role
            -p       --port    [PORT]       Specify the port to connect/listen
            -S       --shost   [SOURCE]     Specify the source host for session selection
            -D       --dhost   [DEST]       Specify the destination host for session selection
            -E       --sport   [SPORT]      Specify the source port for session selection
            -G       --dport   [DPORT]      Specify the destination port for session selection
            -n       --isn     [ISN]        Specify the TCP ISN for session selection
            -c       --count   [NUMBER]     Specify the number of times to repeat the replay
            -H       --hook    [FILE]       Specify the Ruby script to load as hook
            -L       --log                  Enable logging of data sent/receive
            -K       --disable-checksum     Disable NIDS TCP checksum verification
            -T       --timeout [MS]         Set socket read timeout in microsecond
            -Q       --simulate             Simulate Socket I/O only, do not send/recv


    In case the --shost && --dhost && --isn && --sport && --dport parameters are not supplied,
    the program will load all the TCP sessions from file and ask the user to select a session to replay

Getting Started
---------------

    ./wireplay -K --role client --port 80 --target 127.0.0.1 -L -F ./pcap/http.dump

The above runs wireplay with TCP checksum calculation disabled, replaying an
HTTP session from ./pcap/http.dump file.

    ./wireplay --role client -F ./pcap/dcedump.dump --target 172.16.34.129 --port 135

The above example reads a dcedump (Dave Aitel's dcedump) session from the file
dcedump.dump (pcap dump file) and replays it.

What to do with it?
-------------------

 * Fuzzing for Security Bugs
 * General Software Testing
 * Being cool..

Ruby Interface
--------------

First: In order to have a real life example of Wireplay hooking capability and
usage, take a look at hooks/rbhooks/cgen.rb

Wireplay implements a Ruby Interface for writing hooks in Ruby. Hooks are called
before sending and after receiving data.

You can also register hook to be called on error.

Example:

   Hooks register a hook object containing callback methods which are called on
   occurrance of specific events like sending data, received data, error etc.

   Have a look at hooks/rbhooks/*.rb for an idea

Example Ruby Hook
-----------------
    class MySampleHook

      def initialize
        puts ">> MySampleHook initialized"
      end

      def on_start(desc)
        puts ">> MySampleHook start (desc: #{desc.inspect})"
      end

      # 
      # If this method returns nil, then Wireplay assumes data
      # is not changed. If it returns a string, then Wireplay
      # sends the string instead of the original data
      #
      def on_data(desc, direction, data)
        puts ">> MySampleHook data (desc: #{desc.inspect})"
        puts ">> MySampleHook data (direction: #{direction})"
        puts ">> MySampleHook data (data size: #{data.size})"
      end

      def on_stop(desc)
        puts ">> MySampleHook stop (desc: #{desc.inspect})"
        end
      end

    Wireplay::Hooks.register(MySampleHook.new)

As you can see, desc is sent to every event handler method in the above example. desc is actually a
Ruby OpenStruct? object, created in C-land and is similar to the example below:

    irb(main):002:0> desc = OpenStruct.new
    => #<OpenStruct>
    irb(main):003:0> desc.host = "192.168.0.2"
    => "192.168.0.2"
    irb(main):004:0> desc.port = 80
    => 80
    irb(main):005:0> desc.run_count = 10
    => 10
    irb(main):006:0> desc.role = 1
    => 1
    irb(main):007:0> desc.inspect
    => "#<OpenStruct host=\"192.168.0.2\", port=80, run_count=10, role=1>"



Notes
-----

 * libnids-1.23 had does not set certain pointers to NULL during nids_exit()
   and hence refers to invalid free'd memory during next nids_init() and tcp
   capture and crashes. The patched version of libnids in the $(pwd) needs to
   be used until it is fixed upstream.

 * TCP Checksum Offloading: Modern NIC hardwares support TCP/UDP checksum
   calculation in hardware. So OS Network Stack might write packets to NIC
   with incorrect/null checksum expecting the NIC to calculate and re-write
   appropriate checksum before xmit. As a result sniffed TCP packets might
   have incorrect checksums which won't be picked up by NIDS unless
   checksumming is disabled.

 * For modern hardwares, its safe to run wireplay with -K to disabled NIDS
   checksuming by default.
