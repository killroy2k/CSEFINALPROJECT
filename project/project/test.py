import sys
import platform
import geopandas
import shapely

print("Python EXE     : " + sys.executable)
print("Architecture   : " + platform.architecture()[0])
print("Path to geopandas  : " + geopandas.__file__)
print("Path to shapely  : " + shapely.__file__)

input("\n\nPress ENTER to quit")