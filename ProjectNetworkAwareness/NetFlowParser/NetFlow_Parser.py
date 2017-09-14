import argparse, sys, os
from progressbar import *
#same directory
from Parser import Parser

def main():
	parser = argparse.ArgumentParser(description='Parser useful for analyse netflow records as collection, as file. '
												 'It also provides a mechanics to dump the record on a mongodb')
	parser.add_argument('-f', '--file', action="store_true", help='NetFlow file to parse')
	parser.add_argument('-c', '--collection', action="store_true", help='Collection of flows to parse')
	parser.add_argument('-d', '--database', action="store", help='Save flows to database')
	args = vars(parser.parse_args())

	if not len(sys.argv) > 1:
		parser.print_help()
		parser.exit()

	if args['file']:
		try:
			data = open(os.getcwd() +'/../'+ args['file'][0], "rb").read()
		except IOError:
			print('Error: File does not exist.')
			exit()
		else:
			parser = Parser(data)
			parser.parseNetFlowData()
	elif args['database'] is not None:
		print('Starting .....')
		# args['database'] = 'UserProfiling'
		parser = Parser(db_name=args['database'])
		dirs = [name for name in os.listdir(os.getcwd() +'/../Data/'+args['database'])]
		for dir in dirs:
			print(dir)
			for file in sorted(os.listdir(os.getcwd() +'/../Data/'+args['database']+'/'+dir)):
				try:
					data = open(os.getcwd() + '/../Data/'+args['database']+'/' + dir + '/'+ file, "rb").read()
				except IOError:
					print('Error: File does not exist.')
					exit()
				else:
					print(file)
					flows = data.split(b'\n\n')
					for i in range(len(flows)):
						if len(flows[i]) != 76:
							continue
						try:
							parser.parseNetFlowData(data=flows[i], collection_name=dir)
							parser.cleanUp()
						except:
							pass
	else:
		try:
			data = open(os.getcwd() +'/../Data/UserProfiling/'+ args['collection'], "rb").read()
		except IOError:
			print(os.getcwd() +'/../Data/UserProfiling/'+ args['collection'][0])
			print('Error: File does not exist.')
			exit()
		else:
			flows = data.split(b'\n\n')
			#print(len(flows))
			dbname = input('Database Name: ')
			collection = input('Collection Name: ')
			parser = Parser(db_name=dbname)
			for i in range(len(flows)):
				if len(flows[i]) != 76:
					continue
				try:
					parser.parseNetFlowData(data=flows[i], collection_name=collection)
				except:
					pass
				parser.cleanUp()
	exit()


if __name__ == "__main__":
	main()