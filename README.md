Building the project:
  1. cd build
  2. meson ..
  3. ninja
  
  
  Preparations before running the project
  
    1. cp src/gui/tokensso.html /var/www/html/.
  
  
  Running the application
  
    1. cd build/src
    2. ./tokenverification-daemon
    
    
 Introduction:
 
   This application is run as 3 separate processes.
   
   tokenverification-daemon: This is the launcher for the two working processes.
   
   tokenverification-gui:  The Gui process which lets user to authenticate using keycloak server and get the User Details.
   
   tokenverification-server: The server process to validate the token received and retrieve the User Information from the token.
   
   
   Release Notes.
   1. Some times the first time login may not succeed. In that case relogin again and that would succeed.
   2. Initially only the login gui window would be open as per design. The User details Window would come up only after the token is retreived
      and successfully verified. Please wait sometime (a minute max after the login) for that.
   3. Token verification is minimal. Additional bells later :)
   4. There may be sometime the user information would show as unknown. This is during the time when the token is expired. The SW would automatically
      renew the token and the User details would be updated in the window.
   5. Verified the working with Google login and Github login only.
   
   
    
  
