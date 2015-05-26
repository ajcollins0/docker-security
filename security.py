#!/usr/bin/python

import os
import sys
import argparse
import docker
import json
import subprocess

class NoItemFound(Exception):
    
    def __init__(self, name):
        self.name = name

class InternalError(Exception):
    pass

# mail class for execution of contSec
class Runner:

    def __init__(self,HostURL):

        # HostURL is the location of the docker host, by default it is unix://var/run/docker.sock
        try:
            self.client = docker.Client(base_url=HostURL)
            self.dockerInfo = self.client.info()
            self.dockerDriver = self.dockerInfo['Driver']
            self.dockerRoot = self.dockerInfo['DockerRootDir'] 
        except Exception, err:
            print "Error contacting the Docker daemon"
            print err
            sys.exit(1)
            
    # Searches images then containers (order is important) to ensure user input is a valid image/container
    def searchName(self, name):

        try:
            item = self.client.inspect_image(name)
            print "found image for '" + name + "':", item['Id']
            self.getData(item['Id'])   
            return 
        except:
            try:
                item = self.client.inspect_container(name)
                print "found container for '" + name + "':", item['Name'], item['Id']
                self.getData(item['Id'])
                return
            except:
                raise NoItemFound(name)  

    # Grabs the metadata required for dmsetup to properly create a device from docker's pool 
    def getMetaData(self, ID):

        try:
            with open(self.dockerRoot + '/devicemapper/metadata/' + ID) as data_file:    
                    data = json.load(data_file)
            data_file.close()
        except Exception, err:
            print "Error getting device's meta data: "
            print err
            sys.exit(1)
        
        deviceID = data['device_id']
        deviceSize = data['size']

        return deviceID, deviceSize

    # Will create the new device from docker's default pool, then mount the device to a temporary folder stored in the current directory 
    def createDevice(self, deviceID, deviceSize, dockerPool):

        # we are assuming that docker's pool file (example: docker-253:1-920679-pool) is found in /dev/mapper/
        #      Normally the device mapper driver will put all DM devices in /dev/mapper by default!
        # dmsetup create thin --table "0 10737418240 thin /dev/mapper/dockerPool 16"

        try:
            subprocess.call('dmsetup create thin --table \"0 '+ str(deviceSize) + ' thin /dev/mapper/' + dockerPool + ' ' + str(deviceID) + '\"', shell=True)
        except Exception, err:
            print "Error creating device: "
            print err
            sys.exit(1)     

        if not os.path.exists("tempMountPoint/"):
            subprocess.call("mkdir tempMountPoint", shell=True)

        subprocess.call("mount /dev/mapper/thin tempMountPoint/", shell=True)

        pwdOutput = subprocess.check_output(["pwd"])
        pwdOutput = pwdOutput[:-1]

        return pwdOutput + '/tempMountPoint/rootfs/'
    
    # Unmounts the newly created device from the temporary directory, then removes the device
    def removeDevice(self):

        try:
            subprocess.call(["umount", "tempMountPoint/"]) 
            subprocess.call(["dmsetup", "remove", "thin"]) 
        except Exception, err:
            print "Error attempting to unmount and remove device: "
            print err
            print "Attempting to force unmount and device removal"
            try:
                subprocess.call(["umount", "-f", "tempMountPoint/"]) 
                subprocess.call(["dmsetup", "remove", "-f", "thin"]) 
            except Exception, err:
                print "Force unmount and device removal failed"
                print err
                print "Please unmount tempMountPoint and remove device thin prior to running contrSec again"
                sys.exit(1)

    # Runs the yum command to get security errata using 'path' as the root directory of the image/container 
    def runYum(self, path):
        
        try:
            subprocess.call('yum updateinfo list security all --installroot=' + path, shell=True)        
        except Exception, err:
            print "Error getting security data from root file system: "
            print err
            self.removeDevice()
            sys.exit(1)
        
    # Reads dockers device driver, then sends correct path to runYum to get the security errata based on the driver
    def getData(self, ID):

        if self.dockerInfo['Driver'] == 'devicemapper':

            dockerPool = self.dockerInfo['DriverStatus'][0][1]
            deviceID, deviceSize = self.getMetaData(ID)
            rootDir = self.createDevice(deviceID, deviceSize, dockerPool)
            self.runYum(rootDir)
            self.removeDevice()

        elif self.dockerInfo['Driver'] == 'aufs':
            # image/container location is here: dockerRoot/aufs/diff/<id>
            self.runYum(self.dockerRoot + '/aufs/diff/' + ID)
            # return yulu.yulu(itemdirectoryname) 
        elif self.dockerInfo['Driver'] == 'btrfs':
            # image/container location is here: dockerRoot/btrfs/subvolumes/<id>
            self.runYum(self.dockerRoot + '/btrfs/subvolumes/' + ID)
        elif self.dockerInfo['Driver'] == 'vfs':
            # image/container location is here: dockerRoot/vfs/dir/<id>
             self.runYum(self.dockerRoot + '/vfs/dir/' + ID)

    # Runs getData against all containers (running and stopped)
    def runAllContainers(self):
        for container in self.client.containers(all=True):
            print 'Checking container', container['Names'][0], ':', container['Id']
            self.getData(str(container['Id']))

     # Runs getData against all images 
    def runAllImages(self):
        for image in self.client.images():
            print 'Checking image', image['Id']
            self.getData(str(image['Id']))

# Start program here!
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Check security vulnerabilities of Docker containers and images')

    parser.add_argument('IDs', nargs='*', default='[]', help='Get security vulnerabilities for the given image(s) or container(s)')
    parser.add_argument('--Allcon', action='store_true', default=False, help='Get security vulnerabilities for all containers')
    parser.add_argument('--Allim', action='store_true', default=False, help='Get security vulnerabilities for all images')
    parser.add_argument('-H', default='unix://var/run/docker.sock', metavar='host', help='Specify docker host socket to use')

    args = parser.parse_args()

    if (len(sys.argv) < 2):
        parser.print_help()
        sys.exit(1)

    mainRun = Runner(args.H)

    try:
        if (args.Allcon):
            mainRun.runAllContainers()

        if (args.Allim):
            mainRun.runAllImages()

        if (args.IDs is not '[]'):
            for name in args.IDs:
                print "searching for", name 
                mainRun.searchName(name)
            
    except NoItemFound, e:
        print "No container or image found for: " + e.name

    except KeyboardInterrupt, e:
        print ("\n\nExiting on user cancel.")
        sys.exit(1)

