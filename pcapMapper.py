# Import necessary libraries
import dpkt           # dpkt is used to read and parse pcap files
import socket         # socket is used for IP address manipulation
import pygeoip        # pygeoip is used to look up geographical information based on IP addresses

# Initialize a GeoIP database using the 'GeoLiteCity.dat' file
gi = pygeoip.GeoIP('GeoLiteCity.dat')


# Define the main function
def main():
    # Open the pcap file for reading in binary mode
    f = open('capture.pcap', 'rb')

    # Create a pcap reader object to parse the pcap file
    pcap = dpkt.pcap.Reader(f)

    # Define the beginning of the KML file with some styling information
    kmlheader = '<?xml version="1.0" encoding="UTF-8"?> \n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n'\
                '<Style id="transBluePoly">' \
                '<LineStyle>' \
                '<width>1.5</width>' \
                '<color>FF800080</color>' \
                '</LineStyle>' \
                '</Style>'

    # Define the end of the KML file
    kmlfooter = '</Document>\n</kml>\n'

    # Generate the KML document by concatenating the header, IP data, and footer
    kmldoc = kmlheader + plotIPs(pcap) + kmlfooter

    # Print the resulting KML document
    print(kmldoc)


# Function to plot IP addresses in the pcap file
def plotIPs(pcap):
    kmlPts = ''  # Initialize an empty KML string to store placemarks
    for (ts, buf) in pcap:
        try:
            # Parse the Ethernet frame and extract the source and destination IP addresses
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)

            # Generate KML for the connection between source and destination IP addresses
            KML = retKML(dst, src)
            kmlPts = kmlPts + KML
        except:
            pass
    return kmlPts


# Function to generate KML for a connection between two IP addresses
def retKML(dstip, srcip):
    dst = gi.record_by_name(dstip)  # Look up geographical information for the destination IP
    src = gi.record_by_name('97.106.228.165')  # Use a placeholder IP (replace with an actual public IP)

    try:
        # Extract longitude and latitude information for source and destination IPs
        dstlongitude = dst['longitude']
        dstlatitude = dst['latitude']
        srclongitude = src['longitude']
        srclatitude = src['latitude']

        # Create KML placemark for the connection
        kml = (
            '<Placemark>\n'
            '<name>%s</name>\n'
            '<extrude>1</extrude>\n'
            '<tessellate>1</tessellate>\n'
            '<styleUrl>#transBluePoly</styleUrl>\n'
            '<LineString>\n'
            '<coordinates>%6f,%6f\n%6f,%6f</coordinates>\n'
            '</LineString>\n'
            '</Placemark>\n'
        ) % (dstip, dstlongitude, dstlatitude, srclongitude, srclatitude)

        return kml
    except:
        return ''

# Entry point of the script
if __name__ == '__main__':
    main()
