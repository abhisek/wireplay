class HttpFuzzer
   FUZZ_STRINGS = [
      "/.../.../.../.../.../",
      "/.../.../.../.../..." * 100,
      "/.../.../.../.../..." * 50,
      "/.../.../.../.../..." * 1024,
      "/.../.../.../.../..." * 10,
      "/.../.../.../.../..." * 1,
      "../../../../../../../../../../../../etc/hosts%00",
      "../../../../../../../../../../../../etc/hosts",
      "../../../../../../../../../../../../etc/passwd%00",
      "../../../../../../../../../../../../etc/shadow%00",
      "../../../../../../../../../../../../boot.ini%00",
      "../../../../../../../../../../../../localstart.asp%00",
      "//../../../../../../etc/passwd",
      "../../../../../../../winnt/system32/ipconfig.exe",
      "../../../../../../../winnt/system32/",
      "/localstart.asp%20",
      "<script>alert('Hello World');</script>",
      "/\\" * 100,
      "/\\" * 200,
      "/\\" * 300,
      "/\\" * 1000,
      "/\\" * 2000,
      ("%s\n %s\n    %s" % ["A" * 512, "B" * 512, "C" * 512]), # HTTP Header folding bugs?
      ("%s\n %s\n    %s" % ["A" * 100, "B" * 50, "C" * 25]), # HTTP Header folding bugs?
      ("%s\n %s\n    %s" % ["A" * 25, "B" * 512, "C" * 250]), # HTTP Header folding bugs?
      ("%s\n %s\n    %s" % ["A" * 50, "B" * 50, "C" * 50]), # HTTP Header folding bugs?
      "A" * 100,
      "A" * 200,
      "A" * 300,
      "A" * 400,
      "A" * 500,
      "A" * 1000,
      "A" * 2000,
      "A" * 3000,
      "A" * 4000,
   ]

   def initialize
      @started = false
   end

   def on_start(w_desc)
      @started = true
      @slots = Array.new

      cmsg("HttpFuzzer: Received start event")
   end

   def on_stop(w_desc)
      @started = false

      cmsg("HttpFuzzer: Received stop event")
   end

   def on_error(w_desc, error)
      cmsg("HttpFuzzer: Received error event (code: #{error})")
   end

   def on_data(w_desc, direction, data)
      unless @started
         cmsg("HttpFuzzer: Not in started state")
         return
      end
      
      unless (direction == Wireplay::REPLAY_CLIENT_TO_SERVER)
         return
      end

      return do_fuzz_http_request(data)
   end

   private
   def do_fuzz_http_request(data)
      data = data.dup
      request_line = []
      params = []
      
      # Here we will only structurize the HTTP header parts, we won't touch the
      # HTTP data part like FORM parameters in POST etc.
      until data.empty?
         # Get next line from http data seperated by \r\n
         line = data.split("\r\n", 2)[0]
         if line.to_s.empty?
            params << []   # Marker
            break
         end

         # slice off the line from original data
         data.slice!(0, line.size + 2)
         
         # Structurize the HTTP request
         if line =~ /(GET|POST|HEAD|OPTIONS) ([^\s]+) HTTP\/(\d).(\d)/i
            request_line = [$1, $2, [$3, $4]]   
         elsif line =~ /([a-zA-Z0-9]+): (.*)/i
            params << [$1, $2]
         else
            extra << line
         end
      end

      # Do some random spiking here
      #puts ""
      #puts "RequestLine: " + request_line.inspect
      #puts "Params: " + params.inspect
      #puts ""
      if request_line.empty? or params.empty?
         # We don't do fuzzing for invalid http requests
         return nil
      end
      
      request = ""
      request << do_prepare_http_request_line(request_line)
      request << do_prepare_http_params(params)
      request << data
      
      # Save last 5 fuzzed requests
      @slots.shift if @slots.size >= 5
      @slots.push(request)

      return request
   end

   def do_prepare_http_request_line(request_line)
      r = rand(Process.pid()) % 3
      request_line[2] = "HTTP/%d.%d" % [request_line[2][0], request_line[2][1]]

      request_line[r] = get_random_fuzz_string()

      # Heuristic: HTTP path always starts with /
      request_line[1] = ("/" + request_line[1]) unless (request_line[1] =~ /^\//i)

      return (request_line.join(" ") + "\r\n")
   end

   def do_prepare_http_params(params)
      pstr = ""
      r = rand(Process.pid()) % params.size
      params.each do |pp|
         if (pp[0].nil?) and (pp[1].nil?)
            pstr << "\r\n"
            break
         end
         
         if (params[r] == pp)
            p1 = pp[0]
            p2 = pp[1]
            
            x = rand(100) % 3
            if (x == 0)
               p1 = get_random_fuzz_string()
            elsif (x == 1)
               p2 = get_random_fuzz_string()
            else
               p1 = get_random_fuzz_string()
               p2 = get_random_fuzz_string()
            end

            pstr << (p1 + ": " + p2 + "\r\n")
         else
            pstr << (pp[0] + ": " + pp[1] + "\r\n")
         end
      end

      return pstr
   end

   def get_random_fuzz_string()
      r = rand(Process.pid()) % FUZZ_STRINGS.size
      return FUZZ_STRINGS[r]
   end
end

Wireplay::Hooks.register(HttpFuzzer.new)
