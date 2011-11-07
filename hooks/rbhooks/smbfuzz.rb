class SmbFuzz
   def initialize
   end

   def on_start(desc)
      cmsg("SmbFuzzer: Received start event")
   end

   def on_stop(desc)
      cmsg("SmbFuzzer: Received stop event")
   end

   def on_error(desc, error)
      cmsg("SmbFuzzer: Received error event (code: #{error})")
   end

   def on_data(desc, direction, data)
      begin
         _on_data(desc, direction, data)
      rescue ::Exception => e
         cmsg("SmbFuzzer: Exception occurred (#{e.message})")
         nil
      end
   end

   def _on_data(desc, direction, data)
      unless desc.role == Wireplay::ROLE_CLIENT
         cmsg("SmbFuzzer: Cannot run in server role..")
         return nil
      end

      unless direction == Wireplay::REPLAY_CLIENT_TO_SERVER
         # We are fuzzing client data only
         return nil
      end
      
      # Only fuzz header packets, tail data part is not interesting
      unless smb_like?(data)
         cmsg("SmbFuzzer: skipping data..")
         return nil
      end

      smb_fuzz(data)
   end

   private
   def smb_fuzz(data)
      bytes = [0x80, 0x00, 0xff, 0xfe, 0x01]
      
      # 4 bytes of NB header
      # 4 bytes of signature \xffSMB
      nb = 8 + rand(data.size - 8) 
      fb = bytes[rand(bytes.size)]

      cmsg("SmbFuzzer: nb=#{nb} fb=0x%02x" % [fb])

      d = data.dup
      d[nb] = fb

      return d
   end

   def smb_like?(data)
      smb_data = smb_data_from_nbpacket(data)
      smb_data = smb_data.to_s

      smb_data[0 ... 4] == "\xffSMB"
   end

   def smb_data_from_nbpacket(data)
      nbs = data.unpack('CCv')

      msg_type = nbs[0].to_i
      msg_flag = nbs[1].to_i
      msg_size = nbs[2].to_i

      if (msg_type != 0) or (msg_flag != 0) or (msg_size <= 0)
         cmsg("SmbFuzzer: (msg_type = %d) (msg_flag = %d) (msg_size = %d)" % [msg_type, msg_flag, msg_size])
         return nil
      end

      data[4 ... msg_size]
   end
end

Wireplay::Hooks.register SmbFuzz.new
