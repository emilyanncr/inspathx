#!/usr/bin/env ruby

################################################################################
#    Internal Path Discloser (a.k.a inspath) - No more path disclosure anymore
#  
#    license: GPL 
#    released date: 2010-09-28
#
#    (c) Aung Khant, http://yehg.net               
#                                                 
#    YGN Ethical Hacker Group, Yangon, Myanmar
#
#    Check the update via
#    svn checkout http://inspath.googlecode.com/svn/trunk/ inspath   
#
#    Send bugs, suggestions, contributions to inspath @ yehg .net
#        
#    How's it useful?
#    
#    PHP Web application developers sometimes fail to add safe checks against
#    authentications, file inclusion ..etc are prone
#    to reveal possible sensitive information when
#    those applications' URLs are directly requested.
#	 Sometimes, it's a clue to Local File Inclusion vulnerability.
#    For open-source applications, source code can be downloaded and 
#    checked to find such information. 
#    
#    This script will do this job.
#    First you have to download source archived file of your desired OSS.
#    Second, extract it.
#    Third, feed its path to inspath
#    
#    The inspath takes
#    -d argument as source directory (of application)
#    -u arguement as the target base URL (like http://victim.com)
#    -t argument as the number of threads concurrently to run (default is 10)
#
#    It should work well on both Linux and Windows systems.
#
#    Read the related text: 
#	 http://yehg.net/lab/pr0js/view.php/path_disclosure_vulnerability.txt
#
#    Use portable bash versions if you wish:
#    http://www.pentesterscripting.com/discovery/web_requester
#    http://www.pentesterscripting.com/exploitation/bash_web_parameter_fuzzer
#
################################################################################


require 'net/https'
require 'uri'
require 'thread'
require 'find'
require 'logger'
require 'optparse'

def log(s)
  logger = Logger.new($logpath)  
  logger.datetime_format = "%Y-%m-%d %H:%M:%S pid:"
  logger.info(s)
  logger.close
end

def get_url(url)
  begin
    useragent = {'User-Agent'=>'inspath [path disclosure finder - http://yehg.net]'}
    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host,uri.port)
    http.use_ssl= true if uri.scheme == "https"
    http.verify_ssl = OpenSSL::SSL::VERIFY_NONE if uri.scheme == "https"
    req,body = http.get(uri.path,useragent)
    if req.code == "200"
      if /(<b>(notice|warning|parse\serror|fatal\serror)<\/b>:|undefined\s(variable|constant|index|offset)|PHP\s(notice|warning|error))/mi.match(req.body)
        msg = "[*] #{url}"
        log("#{msg}\n\n[html_source]\n#{body}[/html_source]\n\n")          
        puts "\n#{msg}"
      end     
    elsif req.code == "404"
      #uncomment if you want
      #puts "[!404] #{url} - wrong path or file was removed?"
      #puts
    end	
  rescue Exception=>err
    puts err.message
  end  
end

def print_help(s)
  print_banner
  puts s
  puts "\nExample:\nruby inspath.rb -d /sources/phpmyadmin -u http://localhost/phpmyadmin -t 20\n"
  puts "ruby inspath.rb -d c:/sources/phpmyadmin -u http://localhost/phpmyadmin -t 20"
  exit!
end

def print_banner
  puts "\n=============================================================
Internal Path Disclosure Finder
 (c) Aung Khant, aungkhant[at]yehg.net
  YGN Ethical Hacker Group, Myanmar, http://yehg.net/
=============================================================\n\n"
end

def main

begin
  
options = {}  

parser = OptionParser.new do|opts|
  options[:dir] =  nil
  opts.on('-d','--dir /source/app','set source code directory of application') do |dir|    
    options[:dir] = dir
  end
  options[:url] = nil
  opts.on('-u','--url http://site.com','set url') do |url|
    options[:url] = url
  end
  options[:threads] = 10
  opts.on('-t','--threads 20','set thread number(default 10)') do |thr|
    options[:threads] = thr
  end  
end

parser.parse!

print_help(parser.to_s) if options[:dir] == nil
print_help(parser.to_s) if options[:url] == nil 

filter = /\.(php)$/i
sourcepath = options[:dir].to_s
targeturl = options[:url].to_s
maxthread = options[:threads].to_i

sourcepath = sourcepath.gsub(/\\/,'/') # window
if(targeturl[targeturl.length-1,targeturl.length]!='/')
	targeturl = targeturl + '/'
end
if(sourcepath[sourcepath.length-1,sourcepath.length]!='/')
	sourcepath =sourcepath+ '/'
end
$logpath = targeturl.gsub(/(http|https):\/\//,'')
$logpath = $logpath.gsub(/\//,'_') + '.log'

# comment if you want to append logging
if File.exist? $logpath
  File.delete $logpath
end
  
scans  = []
count = 0
reqcount = 1
#################################################################

print_banner()
puts "\n# searching in #{targeturl} at #{Time.now.strftime("%H:%M:%S %m-%d-%Y")}...\n# log file saved as #{$logpath}\n# total threads: #{maxthread}\n\n"    
      
log("TargetURL: #{targeturl}")
log("Date:  #{Time.now.strftime("%H:%M:%S %m-%d-%Y")}\n\n")

Thread.abort_on_exception = true

Find.find(sourcepath) do |f|
  type = case
          when File.file?(f) then
             if filter.match(f)               
                f = f.gsub(sourcepath,targeturl)      
                scans[count] = Thread.new{
                  begin
                    get_url(f)                              
                  rescue Exception=>err
                    puts err.message
                  end
                }
                count=count+1
                reqcount=reqcount+1 
                if (count != 0 && (count%maxthread) == 0)
                    scans.each {|t|t.join;}
                    scans = []
                    count = 0
                end
             end
         else "?"
         end  
end
puts "\n# waiting for child threads to finish .."
scans.each {|t|t.join;print  "."}

sleep(1)

logcontent = IO.readlines($logpath)	
found = logcontent.to_s.scan("[html_source]").count

puts "\n\n# vulnerable url(s) = #{found}"
puts "# total requests = #{reqcount}"
puts "# done at #{Time.now.strftime("%H:%M:%S %m-%d-%Y")}"
log("Vulnerable url(s) = #{found}")
log("Total requests = #{reqcount}")
log("Generated by inspath, path disclosure finder tool")
log("by Aung Khant, http://yehg.net/lab\n\n")

rescue Exception=>err
  puts err.message

end

end

if __FILE__ == $0
  main()
end

