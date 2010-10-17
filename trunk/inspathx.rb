#!/usr/bin/env ruby

################################################################################
#    Internal Path Discloser / Error Hunter
#  
#    license: GPL 
#    released date: 2010-09-28
#
#    (c) Aung Khant, http://yehg.net               
#                                                 
#    YGN Ethical Hacker Group, Yangon, Myanmar
#
#    Check the update via
#    svn checkout http://inspathx.googlecode.com/svn/trunk/ inspathx   
#
#    Send bugs, suggestions, contributions to inspath @ yehg .net
#        
#    How's it useful?
#    
#    Web application developers sometimes fail to add safe checks against
#    authentications, file inclusion ..etc are prone
#    to reveal possible sensitive information when
#    those applications' URLs are directly requested.
#	 Sometimes, it's a clue to File Inclusion vulnerability.
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
#    -l argument as the language [php,asp,aspx,jsp,all] (default is all)
#    -x argument as your desired extensions separated by comma(s) (default : php4,php5,php6,php,asp,aspx,jsp,jspx)
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

require 'net/http'
require 'net/https'
require 'open-uri'
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
    
    useragent = {'User-Agent'=>'inspathx [path disclosure finder/error hunter - http://yehg.net]'}
    uri = URI.parse(url)
    uri.path += '/' if uri.path.size == 0
    http = Net::HTTP.new(uri.host,uri.port)
    http.read_timeout = 180
    http.open_timeout = 180
    http.use_ssl= true if uri.scheme == "https"
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE if uri.scheme == "https"
    req,body = http.get(uri.path,useragent)    
    if req.code =~ /(301|302)/
        puts "-> #{url} | #{req.code.to_s}"
        puts "(Redirect to : " + req.header["location"]  + ")"
        get_url(req.header["location"])
    end
    
    if /(20|50)/.match(req.code.to_s) 
      if (body.length > 5)
         $server_user_name = body.scan(/home\/([0-9a-zA-Z\.\_\-\+]+)\//)[0]
         if body.scan(/(\/[a-zA-Z0-9\.\_]+\/[a-zA-Z0-9\.\_]+\/[a-zA-Z0-9\.\_]+\/[a-zA-Z0-9\.\_]+\/[a-zA-Z0-9\.\_]+\/)/).length > 0
            $server_root = body.scan(/(\/[a-zA-Z0-9\.\_]+\/[a-zA-Z0-9\.\_]+\/[a-zA-Z0-9\.\_]+\/[a-zA-Z0-9\.\_]+\/[a-zA-Z0-9\.\_]+\/)/)[0]
         elsif  body.scan(/(\/[a-zA-Z0-9\.\_]+\/[a-zA-Z0-9\.\_]+\/[a-zA-Z0-9\.\_]+\/[a-zA-Z0-9\.\_]+\/)/).length > 0
            $server_root = body.scan(/(\/[a-zA-Z0-9\.\_]+\/[a-zA-Z0-9\.\_]+\/[a-zA-Z0-9\.\_]+\/[a-zA-Z0-9\.\_]+\/)/)[0]
         elsif  body.scan(/(\/[a-zA-Z0-9\.\_]+\/[a-zA-Z0-9\.\_]+\/[a-zA-Z0-9\.\_]+\/)/).length > 0
            $server_root = body.scan(/(\/[a-zA-Z0-9\.\_]+\/[a-zA-Z0-9\.\_]+\/[a-zA-Z0-9\.\_]+\/)/)[0]
         end
      end 
      case $language
          when /(php4|php5|php6|php)/            
            if /(<b>(notice|warning|parse\serror|fatal\serror)<\/b>:|undefined\s(variable|constant|index|offset)|PHP\s(notice|warning|error))/mi.match(body)
              msg = "[*] #{url}"
              log("#{msg}\n\n[html_source]\n#{body}[/html_source]\n\n")          
              puts "\n#{msg}"
            end         
          when /(asp|aspx)/
            if /(This error page might contain sensitive information because ASP.NET is configured to show verbose error messages using &lt;customErrors mode="Off"|[HttpException]: The file '|<span><H1>Server Error in '\/' Application.<hr width=100% size=1 color=silver><\/H1> |<span><H1>Server Error in '\/|An unknown error occured in this application.|This error was caught by <b>Application Handler<\/b>.<\/p>|Description: <\/font><\/b>An unhandled exception occurred|COMException \(0x80004005\)|The system cannot find the path specified|<h1>Server Error in|Server Error in \'\/\'|<h1>Server Error<\/h1>)/mi.match(body)
              msg = "[*] #{url}"
              log("#{msg}\n\n[html_source]\n#{body}[/html_source]\n\n")          
              puts "\n#{msg}"
            end         
          when /(jsp|jspx)/
            if /(<pre>org\.apache\.jasper\.JasperException|<u>The server encountered an internal error \(\) that prevented it from fulfilling this request\.<\/u>|<h1>HTTP Status 500 - <\/h1>|at java\.lang\.Thread\.run\(Thread\.java\:|at javax\.servlet\.http\.HttpServlet|<PRE>Message Exception occurred in|<H1>500 Internal Server Error<\/H1>|Message Exception occurred|ArgumentException\:)/mi.match(body)
              msg = "[*] #{url}"
              log("#{msg}\n\n[html_source]\n#{body}[/html_source]\n\n")          
              puts "\n#{msg}"
            end          
          else            
            if /(<b>(notice|warning|parse\serror|fatal\serror)<\/b>:|undefined\s(variable|constant|index|offset)|PHP\s(notice|warning|error)|Description: <\/font><\/b>An unhandled exception occurred|COMException \(0x80004005\)|The system cannot find the path specified|<h1>Server Error in|Server Error in \'\/\'|<h1>Server Error<\/h1>|<u>The server encountered an internal error \(\) that prevented it from fulfilling this request\.<\/u>|<h1>HTTP Status 500 - <\/h1>|at java\.lang\.Thread\.run\(Thread\.java\:|at javax\.servlet\.http\.HttpServlet|<PRE>Message Exception occurred in|<H1>500 Internal Server Error<\/H1>|Message Exception occurred|ArgumentException\:)/mi.match(body)
              msg = "[*] #{url}"
              log("#{msg}\n\n[html_source]\n#{body}[/html_source]\n\n")          
              puts "\n#{msg}"
            end              
      end
   
    elsif req.code == "404"
      #uncomment if you want
      #puts "[!404] #{url} - wrong path or file was removed?"
      #puts
    end	
  rescue Exception=>err
    if err.message !~ /end of file reached/
        puts "\n:( -> #{url}\n\ERROR:\n#{err.message}\n"
    end
  end  
end

def print_help(s,p=$0)
  print_banner
  puts s  
  puts "\nExample:\nruby #{p} -d /sources/phpmyadmin -u http://localhost/phpmyadmin -t 20 -l php\n"
  puts "ruby #{p} -d c:/sources/phpmyadmin -u http://localhost/phpmyadmin -t 20 -l php"
  puts "ruby #{p} -d c:/sources/dotnetnuke -u http://localhost/dotnetnuke -t 20 -l aspx"
  puts "ruby #{p} -d /sources/jspnuke -u http://localhost/jspnuke -t 20 -l jsp -x jsp,jspx"
  exit!
end

def print_banner
  puts "\n=============================================================
Path Discloser (a.k.a inspathx) / Error Hunter
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
  options[:language] = 'all'
  opts.on('-l','--language php','set language [php,asp,aspx,jsp,jspx,all] (default all - means scan all)') do |lan|
    options[:language] = lan
  end  

  options[:extension] = 'php4,php5,php6,php,asp,aspx,jsp,jspx'
    opts.on('-x','--extension php','set file extensions (php4,php5,...)  default regex: php4,php5,php6,php,asp,aspx,jsp,jspx ') do |ext|
    options[:extension] = ext
end  

end

parser.parse!

print_help(parser.to_s) if options[:dir] == nil
print_help(parser.to_s) if options[:url] == nil 


sourcepath = options[:dir].to_s
targeturl = options[:url].to_s
maxthread = options[:threads].to_i
$language = options[:language].to_s.downcase()
$extension = options[:extension].to_s.downcase().gsub(",","|")
filter = /\.(#{$extension})$/i

sourcepath = sourcepath.gsub(/\\/,'/') # window

targeturl = 'http://' + targeturl unless targeturl =~ /^htt(p|ps):\/\//i
targeturl += '/' if URI.parse(targeturl).path.size == 0
if(sourcepath[sourcepath.length-1,sourcepath.length]!='/')
	sourcepath =sourcepath+ '/'
end
$logpath = targeturl.gsub(/(http|https):\/\//,'')
$logpath = $logpath.gsub(/\//,'_')
$logpath = $logpath.gsub(/(\:|\;|\~|\!|\@|\$|\%|\*|\^|\(|\)|\'|\"|\/|<|>|\|)/,'-')
if $logpath.length > 32 
 $logpath = $logpath[0,32] + '__.log'
else
 $logpath += '.log'
end

$server_user_name = '' # extracted from strings like /home/victim/www/....
$server_root = '' # will look like /home/victim/www/

# comment if you want to append logging
if File.exist? $logpath
  File.delete $logpath
end
  
scans  = []
count = 0
reqcount = 0
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

select(nil,nil,nil,2)

logcontent = IO.readlines($logpath)	
found = logcontent.to_s.scan("[html_source]").count

$server_user_name = '' if found == 0
$server_root = '' if found == 0

puts "\n\n"
puts "! Username detected = #{$server_user_name}" unless $server_user_name == ''
puts "! Server path extracted = #{$server_root}" unless $server_root == ''
puts "\n# vulnerable url(s) = #{found}"
puts "# total requests = #{reqcount}"
puts "# done at #{Time.now.strftime("%H:%M:%S %m-%d-%Y")}"
log("! Username detected = #{$server_user_name}") unless $server_user_name == ''
log("! Server path extracted = #{$server_root}") unless $server_root == ''
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

