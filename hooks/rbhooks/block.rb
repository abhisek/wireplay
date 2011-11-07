class FuzzBlock
   FUZZ_STRINGS = [
      "A" * 100,
      "X" * 100
   ]

   def initialize
      @@tokens = []
      @@token_idx = 0
      @@fuzz_idx = 0
      @@orig_data = ""
   end

   def prepare_for(data, tokens)
      @@tokens = tokens
      @@orig_data = data
   end

   def get_next_fuzz_string
      return nil if @@token_idx >= @@tokens.size
      return nil if @@fuzz_idx >= FUZZ_STRINGS.size

      ret = @@orig_data.gsub(@@tokens[@@token_idx], FUZZ_STRINGS[@@fuzz_idx])

      @@fuzz_idx += 1
      if @@fuzz_idx == FUZZ_STRINGS.size
         @@token_idx += 1
         @@fuzz_idx = 0
      end

      ret
   end
end

if __FILE__ == $0
   request = %Q{GET /index HTTP/1.1
Host: localhost
User-Agent: Test
}
   tokens = []

   # Split the string by newline
   http_lines = request.split("\n")

   # Tokenize the VERB line
   verb_line = http_lines.shift
   verb_line =~ /^([^\s]+)\s{1}([^\s+]+)\s{1}(HTTP)\/(\d.\d)/
   tokens += [$1, $2, $3, $4]

   # Tokenize the headers
   http_lines.each do |line| 
      if line =~ /([^:]+): (.*)/
         tokens.push($1.to_s.strip)
         tokens.push($2.to_s.strip)
      end
   end
   
   fb = FuzzBlock.new
   fb.prepare_for(request.to_s, tokens)

   while (str = fb.get_next_fuzz_string) != nil
      puts str

      $stdin.readline
   end
end
