require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Tcp

  def initialize(info={})
    super(update_info(info,
                      'Name'         => 'Redis-server Authentication Scanner',
                      'Description'  => %q{
        This module will test Redis-server logins on a range of machines and report successful logins.
                      },
                        'Author'       => [ 'firebroo' ],
                        'License'      => MSF_LICENSE
                     ))

    register_options(
      [
        Opt::RPORT(6379),
        OptString.new('PASSWORD', [ true, "redis server  password", "foobared"]),
        OptString.new('PASS_FILE', [ false, "redis server password file", ""]),
      ], self.class)

    deregister_options('RHOST')
  end

  def get_info(ip)
    info = "info\r\n"
    sock.put(info)
    data = sock.get_once
    print_good("#{ip}:#{datastore['RPORT']}\nRedis Server Information #{data}")
  end

  def login?(password)
    auth = "auth #{password}\r\n"
    sock.put(auth)
    data = sock.get_once
    if data =~ /\-ERR\sinvalid\spassword/
      return false
    else
      return true
    end
  end

  def run_host(ip)
    print_status("Scanning IP: #{ip.to_s}")
    begin
      pkt = "ping\r\n"
      connect
      sock.put(pkt)
      res = sock.get_once
      if res =~ /PONG/
        get_info ip
      elsif res =~ /NOAUTH Authentication/
        if login? datastore['PASSWORD']
          print_good("#{ip}:#{datastore['RPORT']}\tPassword is #{datastore['PASSWORD']}(Redis server \ 
                               is using the default password of foobared)")
          get_info ip
        else
          if datastore['PASS_FILE'] != ""
            IO.foreach(datastore['PASS_FILE']) do |block| 
              if login? block
                print_good("#{ip}:#{datastore['RPORT']}\tPassword is #{block}")
                get_info ip
                break
              end
            end
          end
        end
      else
        print_error "#{ip} does not have a Redis server"
      end
      disconnect

    rescue ::Exception => e
      print_error "Unable to connect: #{e.to_s}"
    end
  end
end
