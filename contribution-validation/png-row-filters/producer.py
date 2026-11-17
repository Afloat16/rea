import base64, hashlib, io, json, pathlib, struct, sys, zlib
from PIL import Image, ImageChops, ImageDraw, __version__
out=pathlib.Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
def digest(b): return hashlib.sha256(b).hexdigest()
def chunk(kind,data):
    return struct.pack(">I",len(data))+kind+data+struct.pack(">I",zlib.crc32(kind+data))
def filter_counts(data):
    p=8; pieces=[];width=height=channels=0
    while p<len(data):
        length=struct.unpack(">I",data[p:p+4])[0];kind=data[p+4:p+8];value=data[p+8:p+8+length]
        if kind==b"IHDR": width,height=struct.unpack(">II",value[:8]);channels={2:3,6:4}[value[9]]
        if kind==b"IDAT":pieces.append(value)
        p+=length+12
    raw=zlib.decompress(b"".join(pieces));stride=width*channels+1
    return {str(f):sum(raw[y*stride]==f for y in range(height)) for f in range(5)}
def oracle(left,right,threshold):
    delta=ImageChops.difference(left.convert("RGBA"),right.convert("RGBA"))
    channels=delta.split()
    maximum=max(c.getextrema()[1] for c in channels)
    total=sum(sum(i*n for i,n in enumerate(c.histogram())) for c in channels)
    mask=Image.new("L",delta.size,0)
    for c in channels:mask=ImageChops.lighter(mask,c.point(lambda v:255 if v>threshold else 0))
    count=left.width*left.height;changed=count-mask.histogram()[0]
    return {"status":"different" if changed else "identical","before":{"width":left.width,"height":left.height},"after":{"width":right.width,"height":right.height},"channel_threshold":threshold,"compared_pixels":count,"changed_pixels":changed,"changed_ratio":changed/count,"maximum_channel_delta":maximum,"mean_absolute_channel_delta":total/(count*4)}
cases=[]
for mode,width,height in [("RGB",640,360),("RGB",1920,1080),("RGBA",1920,1080)]:
    image=Image.new(mode,(width,height),(240,242,245) if mode=="RGB" else (240,242,245,255));draw=ImageDraw.Draw(image)
    for y in range(0,height,31):
        colour=(y%256,(y*13)%256,(y*29)%256)
        if mode=="RGBA":colour=(*colour,127+y%129)
        draw.rectangle((17,y,width-25,min(y+17,height-1)),fill=colour)
        draw.text((35,y+3),"Observed PNG scanline reconstruction - 0123456789",fill=(0,0,0) if mode=="RGB" else (0,0,0,255))
    modified=image.copy();ImageDraw.Draw(modified).rectangle((width//3,height//3,width//2,height//2),fill=(15,46,91) if mode=="RGB" else (15,46,91,153))
    name=f"{mode}-{width}x{height}"
    for side,im in [("before",image),("after",modified)]:
        im.save(out/f"{name}-{side}.png",compress_level=6)
    for scenario,right,threshold in [("identical",image,0),("changed",modified,3)]:
        left_path=f"{name}-before.png";right_path=f"{name}-before.png" if scenario=="identical" else f"{name}-after.png"
        left_bytes=(out/left_path).read_bytes();right_bytes=(out/right_path).read_bytes()
        cases.append({"name":name+"-"+scenario,"before":left_path,"after":right_path,"oracle":oracle(image,right,threshold),"producer":"Pillow "+__version__,"input_sha256":[digest(left_bytes),digest(right_bytes)],"filters":[filter_counts(left_bytes),filter_counts(right_bytes)]})
(out/"cases.json").write_text(json.dumps(cases,indent=2))
# Fixed all-filter vectors come from a separate encoder; Pillow decodes and checks each.
vectors=[]
for channels in [3,4]:
    width,height=4,3
    pixels=bytes((i*73+(i//7)*29)%256 for i in range(width*height*channels))
    def predictor(kind,a,b,c):
        if kind==0:return 0
        if kind==1:return a
        if kind==2:return b
        if kind==3:return (a+b)//2
        p=a+b-c;dist=[abs(p-a),abs(p-b),abs(p-c)]
        return [a,b,c][dist.index(min(dist))]
    for kind in range(5):
        rows=bytearray()
        for y in range(height):
            rows.append(kind)
            for x in range(width*channels):
                at=y*width*channels+x
                a=pixels[at-channels] if x>=channels else 0
                b=pixels[at-width*channels] if y else 0
                c=pixels[at-width*channels-channels] if y and x>=channels else 0
                rows.append((pixels[at]-predictor(kind,a,b,c))&255)
        header=struct.pack(">IIBBBBB",width,height,8,2 if channels==3 else 6,0,0,0)
        png=b"\x89PNG\r\n\x1a\n"+chunk(b"IHDR",header)+chunk(b"IDAT",zlib.compress(bytes(rows)))+chunk(b"IEND",b"")
        decoded=Image.open(io.BytesIO(png));decoded.load();assert decoded.tobytes()==pixels
        expected=decoded.convert("RGBA").tobytes()
        vectors.append({"channels":channels,"filter":kind,"png":base64.b64encode(png).decode(),"rgba":list(expected),"producer":"Independent PNG encoder, decoded byte-for-byte by Pillow "+__version__})
(out/"vectors.json").write_text(json.dumps(vectors,indent=2))
print(json.dumps({"producer":"Pillow "+__version__,"cases":len(cases),"vectors":len(vectors),"public_oracles":True}))
