<h1>Thingsboard Arduino/ESP32 Compatible PlatformIO Provisioner</h1>

<h3 align=center>The following Python script allows for fast flashing and provisioning of devices.</h3>

The script accesses the Thingsboard instance using the REST API, logs in, creates a new customer, device, places the new device in the specified device profile, and copies the new Access Token into a selected .ino file where the variable #define TOKEN ""; is. Then, it flashes the updated code to the device using a specified com port.

Please confirm all dependencies declared at the beginning of the Provisioner script are met.

The device profiles located in the drop-down can be changed in the provisioner.py script on line <12>

Please follow PlatformIO documentation to setup the environment for uploading your .ino file to your device. These lines can be changed in the provisioner code from line <209> to <216>. 

Additionally, the variables inside the script can be changed for other Thingsboard Tenant access to stick. The script runs the default tenant credentials from the start.

<em><b>This code is unsupported, and I am not responsible for any failures or damage that may occur from flashing your MCU with PlatformIO or the provisioner script. Please use at your own risk.</b></em>

