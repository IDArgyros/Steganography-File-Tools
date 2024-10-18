from PIL import Image, ImageTk
import piexif
import customtkinter
import tkinter
import tkinter.messagebox
from tkinter import filedialog
import random
import string
import os
from playsound import playsound
import simpleaudio as sa
import webbrowser
import wave
from pydub import AudioSegment
import ffmpeg
import subprocess
import shlex
import json
import PyPDF2
from moviepy.editor import VideoFileClip
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import binascii


aes_mode_mapping = {
    'ECB': AES.MODE_ECB,
    'CBC': AES.MODE_CBC,
    'CFB': AES.MODE_CFB,
    'OFB': AES.MODE_OFB
}


def aes_is_valid_key(key):

    # Check if the key length is valid
    if len(key) not in [32, 48, 64]:
        return False

    # Check if the key contains only hexadecimal characters
    try:
        int(key, 16)
        return True
    except ValueError:
        return False


def aes_ciphertext_is_hexadecimal(hex_string):

    try:
        int(hex_string, 16)
        return True
    except ValueError:
        return False


def encrypt(plaintext, key, mode):
    cipher = AES.new(key, mode)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    if mode != AES.MODE_ECB:
        return cipher.iv + ciphertext
    return ciphertext


def decrypt(ciphertext, key, mode):
    if mode != AES.MODE_ECB:
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, mode, iv)
        plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    else:
        cipher = AES.new(key, mode)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext


def hex_to_bytes(hex_string):
    try:
        return bytes.fromhex(hex_string)
    except ValueError:
        print("Invalid hexadecimal format. Please enter a valid hexadecimal string.")
        exit()


def encode_text_to_base64(text):
    # Encode text to bytes and then encode to Base64
    encoded_bytes = base64.b64encode(text.encode('utf-8'))
    # Convert bytes to string
    encoded_text = encoded_bytes.decode('utf-8')
    return encoded_text


def decode_text_from_base64(encoded_text):
    # Decode Base64 to bytes and then decode to text
    decoded_bytes = base64.b64decode(encoded_text.encode('utf-8'))
    # Convert bytes to string
    decoded_text = decoded_bytes.decode('utf-8')
    return decoded_text


def extract_audio(video_path):
    try:
        # Load the video clip
        video_clip = VideoFileClip(video_path)

        # Extract the audio
        audio_clip = video_clip.audio

        # Write the extracted audio to a file
        audio_clip.write_audiofile("extracted_audio.mp3")

        # Close the video clip
        video_clip.close()

    except Exception as e:
        show_error("Error:" + str(e.__cause__))


def encode_text_in_metadata(video_path, tag_name, text_to_hide):

    standard_tags = ["comment", "genre", "title", "description"]

    # Get the file extension from the video path
    _, extension = os.path.splitext(video_path)

    output_path = "output_video_with_metadata" + extension

    if tag_name.lower() not in standard_tags:
        show_error(f"Error: '{tag_name}' is not a standard metadata tag name.")
        return

    tag_name = tag_name.lower()

    try:
        # Construct the ffmpeg command to add or modify a metadata tag
        command = f'ffmpeg -i "{video_path}" -metadata {tag_name}="{text_to_hide}" -c copy "{output_path}" -y'

        # Execute the ffmpeg command using subprocess
        subprocess.run(shlex.split(command), check=True)
        show_message(f'Resulting file saved as {output_path}')

    except subprocess.CalledProcessError as e:
        print("Error:", e)
        show_error("Error, Return Code: " + str(e.returncode))


def print_all_video_metadata_tags(video_path):

    result_video_tags = ""

    try:
        # Construct the ffprobe command to extract metadata
        command = f'ffprobe -v quiet -print_format json -show_format -show_streams "{video_path}"'

        # Execute the ffprobe command using subprocess
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        # Parse the JSON output to extract metadata
        metadata = json.loads(result.stdout)

        # Check if the format tags exist in the metadata
        if 'format' in metadata:
            format_tags = metadata['format']
            if 'tags' in format_tags:
                tags = format_tags['tags']
                # Print all tags
                for tag, value in tags.items():
                    result_video_tags = result_video_tags + f"{tag}: {value}\n------------------------------\n"

    except subprocess.CalledProcessError as e:
        print("Error:", e)
        show_error("Error, Return Code: " + str(e.returncode))

    return result_video_tags


def embed_text_in_pdf(pdf_path, text_to_embed, tag):
    # Open the PDF file
    with open(pdf_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        writer = PyPDF2.PdfWriter()

        # Copy all pages from the original PDF
        writer.append_pages_from_reader(reader)
        metadata = reader.metadata
        writer.add_metadata(metadata)

        # Embed text in metadata
        writer.add_metadata({"/" + tag: text_to_embed})

        # Write the modified PDF to a new file
        with open('output.pdf', 'wb') as output_file:
            writer.write(output_file)


def display_pdf_metadata(pdf_path):

    result_metadata = ""

    # Open the PDF file
    with open(pdf_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)

        # Extract metadata from the first page
        metadata = reader.metadata

        # Display all metadata tags and their content
        for tag, content in metadata.items():
            result_metadata = result_metadata + f"{tag}: {content}\n------------------------------\n"

    return result_metadata


def hide_text_in_audio(audio_file_path, text_to_hide, output_file):
    for char in text_to_hide:
        if ord(char) < 32 or ord(char) > 127:
            show_error("Only standard printable ASCII characters supported!")
            return

    # Open the audio file for reading
    with wave.open(audio_file_path, 'rb') as audio:
        # Read audio data
        audio_data = audio.readframes(audio.getnframes())

    # Convert text to binary, append ASCII code for end of transmission character
    binary_text = ''.join(format(ord(char), '08b') for char in text_to_hide) + '00000100'
    #print("Binary text:", binary_text)

    # Convert audio data to bytearray
    audio_bytes = bytearray(audio_data)

    # Check if there's enough space in the audio data to embed the text
    if len(binary_text) > len(audio_bytes):
        print("Text is too long to hide in audio file.")
        show_error("Text is too long to hide in audio file.")

    # Embed binary text into audio data
    for i in range(len(binary_text)):
        audio_bytes[i] = (audio_bytes[i] & 0xFE) | int(binary_text[i])
        # print("Modified byte:", audio_bytes[i])

    # Write modified audio data to output file
    with wave.open(output_file, 'wb') as output_audio:
        output_audio.setparams(audio.getparams())
        output_audio.writeframes(audio_bytes)

    show_message("Audio file with text saved as Resulting_Audio.wav.")


def decode_text_from_audio(audio_file_path):

    result = ''

    # Open the audio file for reading
    with wave.open(audio_file_path, 'rb') as audio:
        # Read audio data
        audio_data = audio.readframes(audio.getnframes())

    # Iterate through each byte of audio data
    current_byte = ''
    for byte in audio_data:
        # Extract LSB of the byte
        lsb = byte & 0x01
        # Append LSB to current_byte
        current_byte += str(lsb)
        # If current_byte forms a full ASCII character (8 bits), print it
        if len(current_byte) == 8:
            char = chr(int(current_byte, 2))

            current_byte = ''  # Reset current_byte for the next character

            if ord(char) == 4:
                # End of Transmission
                return result

            #print(char, end="")

            result += char

            if ord(char) < 32 or ord(char) > 127:
                return result

    return result


def integer_to_20_bit_string(integer):
    binary_string = bin(integer)[2:]

    # pad the binary number to 10 bits
    padded = "{:0>{}}".format(binary_string, 20)

    # return the reversed string
    return padded[::-1]


def add_text_exif(image_path, value_of_tag):
    # Open the image
    img = Image.open(image_path)

    try:
        # Load existing EXIF data
        exif_dict = piexif.load(img.info["exif"])
    except KeyError:
        # If 'exif' key is not found, create an empty EXIF dictionary
        exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "Interop": {}, "1st": {}, "thumbnail": None}

    # Add the custom text tag
    exif_dict["0th"][piexif.ImageIFD.Make] = value_of_tag

    # Convert the dictionary to bytes
    exif_bytes = piexif.dump(exif_dict)

    # Convert image to RGB mode
    img = img.convert("RGB")

    # Save the image with the new EXIF data
    img.save("image_with_text" + os.path.splitext(image_path)[1], exif=exif_bytes)


def extract_text_exif(image_path):
    text_4.delete("1.0", "end")

    try:
        # Open the image
        img = Image.open(image_path)

        # Load existing EXIF data
        exif_dict = piexif.load(img.info["exif"])

        # Check if the tag_name exists in the EXIF data
        for name_of_tag in exif_dict:
            try:
                # Retrieve the tag value
                value = exif_dict[name_of_tag].get(piexif.ImageIFD.Make, None)
                print('{' + name_of_tag + "} : " + str(value))
                text_4.insert(tkinter.END, '{' + name_of_tag + "} : " + str(value) + '\n')

            except AttributeError:
                print(f"Error: Unable to retrieve value for tag '{name_of_tag}'")
                text_4.insert(tkinter.END, "Error: Unable to retrieve value for tag '{" + name_of_tag + "}'\n")

    except KeyError:
        print("Error: 'exif' information not found in the image metadata.")
        text_4.insert(tkinter.END, "Error: 'exif' information not found in the image metadata." + '\n')
        show_error("'exif' information not found in the image metadata.")

    except Exception as e:
        print("An error occurred:", e)
        text_4.insert(tkinter.END, "An error occurred\n")
        show_error("An error occurred:" + str(e))


def get_text_length(image):
    binary_length = ''

    s = 0

    for i in range(image.width):
        for j in range(image.height):
            r, g, b = image.getpixel((i, j))

            if s < 10:

                r_lsb = r & 1

                b_lsb = b & 1

                binary_length = str(b_lsb) + str(r_lsb) + binary_length

                s += 1
            else:
                return int(binary_length, 2)


def text_to_binary_string(text):
    binary_ascii_string = ''.join(bin(ord(char))[2:].zfill(8) for char in text)
    return binary_ascii_string


def binary_string_to_text(binary_string):
    result_text = ''

    binary_char = ''

    for i in range(len(binary_string)):

        binary_char += str(int(binary_string[i], 2))

        if len(binary_char) == 8:
            result_text += chr(int(binary_char, 2))

            binary_char = ''

    return result_text


def get_initial_green_values(image_path):
    # Open the image
    image = Image.open(image_path)

    # Get the green channel values for each pixel
    green_values = []

    for i in range(image.width):
        for j in range(image.height):
            # Get the RGB values for the pixel
            r, g, b = image.getpixel((i, j))

            g = format(g, '08b')

            green_values.append(g)

    return green_values


# Image decoding function to get the embedded text
def decode_text(encoded_image_path):
    image = Image.open(encoded_image_path)

    i = 0

    result_binary_text = ''

    binary_character = ''

    # Get text length

    print("Decode text function, decoded length is:", get_text_length(image))

    length = get_text_length(image)
    len_index = 0

    while i in range(image.width):
        for j in range(image.height):

            if len_index == length:
                show_message("Text decoded successfully!")

                decode_progressbar.set(1)

                return result_binary_text

            r, g, b = image.getpixel((i, j))

            g_lsb = g & 1

            if len(binary_character) < 8:

                binary_character += str(g_lsb)

            else:

                # print("entered this else")

                result_binary_text += binary_character

                binary_character = str(g_lsb)

                decode_progressbar.set(len_index / length)

                # Decode only as much as needed.

                if len_index < length:
                    len_index = len_index + 1

        i = i + 1


# Image encoding function to hide the text
def embed_text(image_path, text):
    # Open the image
    image = Image.open(image_path)

    if check_input_text(text) == 0:
        print("Only printable and standard (non-extended) ASCII characters are supported!")

        show_error("Only printable and standard (non-extended) ASCII characters are supported!")

        return None

    # I need 10 pixels to encode the length of text
    if (image.width * image.height) < 10:
        print("Size of image too small!")

        show_error("Size of image too small!")

        return None

    if (8 * len(text)) >= (image.width * image.height):
        print("Length of text too big for this size of image!")

        show_error("Length of text too big for this size of image!")

        return None

    if len(text) >= 1048575:
        print("Length of text too big!")

        show_error("Length of text too big!")

        return None

    # Get the mode of the image
    image_mode = image.mode

    print("Image mode:", image_mode)

    # Ensure the image is in RGB mode
    image = image.convert("RGB")

    # initialize index to use for iterating through text_binary
    bin_index = 0

    # used to embed the length
    len_index = 0

    # Get the green channel values for each pixel
    green_values = []

    # Create a new image with the same size and mode
    modified_image = Image.new("RGB", image.size)

    i = 0

    text_binary = text_to_binary_string(text)

    length_binary = integer_to_20_bit_string(len(text))

    print("Embed text function, length_binary:", length_binary)
    print("len(text):", len(text))

    while i in range(image.width):
        for j in range(image.height):

            # Get the RGB values for the pixel
            r, g, b = image.getpixel((i, j))

            # Encode the length at the beginning
            if len_index < 20:

                if length_binary[len_index] == '1':

                    r = r | 1
                else:

                    r = r & (~1)

                if length_binary[len_index + 1] == '1':

                    b = b | 1
                else:

                    b = b & (~1)

                len_index = len_index + 2

            if bin_index < len(text_binary):

                # Modify the pixel in the final image
                if text_binary[bin_index] == '1':

                    modified_g = g | 1
                else:

                    modified_g = g & (~1)

                bin_index = bin_index + 1

                modified_image.putpixel((i, j), (r, modified_g, b))

                g = format(modified_g, '08b')

                green_values.append(g)

            else:

                modified_image.putpixel((i, j), (r, g, b))
        i += 1

    file_extension = os.path.splitext(image_path)[1]

    print("Image file extension:", file_extension)

    modified_image.save("modified_image.png")

    return green_values


def check_input_text(text):
    for char in text:

        code = ord(char)
        if (code < 32) or (code > 127):
            return 0

    return 1


def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.webp;*.jpg;*.jpeg;*.png;*.gif")])
    if file_path:
        display_image(file_path)


ui_aes_option = AES.MODE_ECB


def change_aes_option_event(new_event):
    global ui_aes_option

    ui_aes_option = aes_mode_mapping[new_event]

    print(ui_aes_option)


swapped_aes = 0


def aes_swap_event():
    global swapped_aes

    if swapped_aes == 0:
        swapped_aes = 1
        aes_textbox.delete("1.0", "end")
        aes_textbox.insert("0.0", "Enter hexadecimal ciphertext to decrypt here...")
        aes_textbox2.delete("1.0", "end")
        aes_textbox2.insert("0.0", "Decrypted text will appear here...")
        aes_button.configure(text="Decrypt Text")
    else:
        swapped_aes = 0
        aes_textbox.delete("1.0", "end")
        aes_textbox.insert("0.0", "Enter text to encrypt with AES...")
        aes_textbox2.delete("1.0", "end")
        aes_textbox2.insert("0.0", "Encrypted text will appear here...")
        aes_button.configure(text="Encrypt Text")


def encrypt_aes_ui():

    if not aes_is_valid_key(aes_textbox3.get("1.0", "end").strip()):
        show_error("Not a valid key, must be 32/48/64 hexadecimal digits.")
        return

    aes_key_bytes = hex_to_bytes(aes_textbox3.get("1.0", "end").strip())

    if swapped_aes == 0:
        aes_plaintext = aes_textbox.get("1.0", "end").strip()
        aes_plaintext = aes_plaintext.encode('utf-8')
        aes_textbox2.delete("1.0", "end")
        aes_textbox2.insert("0.0", binascii.hexlify(encrypt(aes_plaintext, aes_key_bytes, ui_aes_option)).decode())
    else:
        aes_ciphertext = aes_textbox.get("1.0", "end").strip()

        if not aes_ciphertext_is_hexadecimal(aes_ciphertext):
            show_error("Ciphertext is not valid hexadecimal.")
            return

        aes_ciphertext = binascii.unhexlify(aes_ciphertext)
        aes_textbox2.delete("1.0", "end")
        aes_textbox2.insert("0.0", decrypt(aes_ciphertext, aes_key_bytes, ui_aes_option).decode())


swapped_base64 = 0


def base64_swap_event():
    global swapped_base64

    if swapped_base64 == 0:
        swapped_base64 = 1
        base64_textbox.delete("1.0", "end")
        base64_textbox.insert("0.0", "Enter text to decode from Base64...")
        base64_textbox2.delete("1.0", "end")
        base64_textbox2.insert("0.0", "Decoded text will appear here...")
        base64_button.configure(text="Decode Text")
    else:
        swapped_base64 = 0
        base64_textbox.delete("1.0", "end")
        base64_textbox.insert("0.0", "Enter text to encode in Base64...")
        base64_textbox2.delete("1.0", "end")
        base64_textbox2.insert("0.0", "Encoded text will appear here...")
        base64_button.configure(text="Encode Text")


def encode_base64_ui():

    if swapped_base64 == 0:
        base64_text_to_encode = base64_textbox.get("1.0", "end").strip()
        base64_textbox2.delete("1.0", "end")
        base64_textbox2.insert("0.0", encode_text_to_base64(base64_text_to_encode))

    else:
        base64_text_to_encode = base64_textbox.get("1.0", "end").strip()
        base64_textbox2.delete("1.0", "end")
        base64_textbox2.insert("0.0", decode_text_from_base64(base64_text_to_encode))


def open_video_file_to_extract_audio():
    file_path = filedialog.askopenfilename(filetypes=[("Video files", "*.mp4;*.wmv;*.mov;*.avi;*.avchd;*.flv;*.webm")])
    if file_path:
        extract_audio(file_path)
        show_message("Audio saved as extracted_audio.mp3")


current_video_file_path = None

video_tag = "comment"


def change_video_tag_event(new_tag):
    global video_tag

    video_tag = new_tag.lower()
    print(video_tag)


def open_video_to_add_tag():
    global current_video_file_path

    file_path = filedialog.askopenfilename(filetypes=[("Video files", "*.mp4;*.wmv;*.mov;*.avi;*.avchd;*.flv;*.webm")])
    if file_path:
        current_video_file_path = file_path
        video_add_metadata_label2.configure(text=os.path.basename(file_path))


def add_video_tag_ui():

    global current_video_file_path

    if current_video_file_path is None:
        show_error("No video file selected!")
        return

    video_metadata_text = video_add_metadata_text.get("1.0", "end").strip()

    encode_text_in_metadata(current_video_file_path, video_tag, video_metadata_text)

    current_video_file_path = None

    video_add_metadata_label2.configure(text="-")
    video_add_metadata_text.delete("1.0", "end")


def open_video_to_see_tags_ui():
    file_path = filedialog.askopenfilename(filetypes=[("Video files", "*.mp4;*.wmv;*.mov;*.avi;*.avchd;*.flv;*.webm")])

    if file_path:
        video_see_metadata_text.delete("1.0", "end")
        video_see_metadata_text.insert("0.0", print_all_video_metadata_tags(file_path))


current_pdf_path = None


def open_pdf_file_to_add_tag():
    global current_pdf_path

    file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
    if file_path:
        PDF_label2.configure(text=os.path.basename(file_path))
        current_pdf_path = file_path


def add_pdf_tag_ui():

    global current_pdf_path

    if current_pdf_path is None:
        show_error("No PDF file selected!")
        return

    text_to_embed_to_pdf = PDF_text_to_embed.get("1.0", "end").strip()

    tag_to_add_to_pdf = PDF_tag_name.get("1.0", "end").strip()

    embed_text_in_pdf(current_pdf_path, text_to_embed_to_pdf, tag_to_add_to_pdf)

    show_message("Resulting file saved as output.pdf")

    current_pdf_path = None

    PDF_text_to_embed.delete("1.0", "end")
    PDF_tag_name.delete("1.0", "end")
    PDF_label2.configure(text="-")


def open_pdf_to_see_tags_ui():
    file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
    if file_path:
        PDF_decode_text.delete("1.0", "end")
        PDF_decode_text.insert("0.0", display_pdf_metadata(file_path))


def open_file_for_decoding():
    file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png")])
    if file_path:
        # decode the text here
        print("decoding")
        text_2.delete("1.0", "end")
        text_2.insert("0.0", binary_string_to_text(decode_text(file_path)))


def open_file_to_add_tag():
    file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.webp;*.jpg;*.jpeg;*.png;*.gif")])
    if file_path:
        print("adding tag")
        display_image_for_exif_tag(file_path)


def open_file_to_see_tags():
    file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.webp;*.jpg;*.jpeg;*.png;*.gif")])
    if file_path:
        print("seeing tags")
        # text_4.insert("0.0", "EXIF tags will appear here...")
        extract_text_exif(file_path)


current_audio_path = None


def open_file_to_see_audio():
    global current_audio_path

    file_path = filedialog.askopenfilename(filetypes=[("Audio files", "*.wav;*.mp3")])
    if file_path:
        print("inspecting audio")
        embed_audio_label2.configure(text=os.path.basename(file_path))
        current_audio_path = file_path


def add_text_to_audio_ui():
    global current_audio_path

    if current_audio_path is None:
        show_error("No audio file selected!")
        return

    _, extension = os.path.splitext(str(current_audio_path))

    print("Audio extension:", extension)

    if (extension != ".wav") and (extension != ".mp3"):
        show_error("Only .wav and .mp3 files supported!")
        return

    text_to_embed_to_audio = audio_text_to_embed.get("1.0", "end").strip()
    print("Text to embed in audio:", text_to_embed_to_audio)

    if extension == ".mp3":
        sound = AudioSegment.from_mp3(current_audio_path)
        sound.export("___intermediate_file.wav", format="wav")
        hide_text_in_audio("___intermediate_file.wav", text_to_embed_to_audio, "Resulting_Audio.wav")
        os.remove("___intermediate_file.wav")
        embed_audio_label2.configure(text="-")
        current_audio_path = None
        audio_text_to_embed.delete("1.0", "end")
        return

    if extension == ".wav":
        hide_text_in_audio(current_audio_path, text_to_embed_to_audio, "Resulting_Audio.wav")
        embed_audio_label2.configure(text="-")
        current_audio_path = None
        audio_text_to_embed.delete("1.0", "end")
        return


def open_audio_to_see_text_ui():
    file_path = filedialog.askopenfilename(filetypes=[("Audio files", "*.wav")])
    if file_path:
        audio_decode_text.delete("1.0", "end")
        audio_decode_text.insert("0.0", decode_text_from_audio(file_path))


current_image_tag = None
image_path_ui_tag = None


def display_image_for_exif_tag(tag_file_path):
    global current_image_tag
    global image_path_ui_tag

    print(tag_file_path)

    # Open the new image
    new_image = Image.open(tag_file_path)
    new_image.thumbnail((200, 100))  # Resize the image if needed

    # Create a CTkImage from the new image
    new_ctk_image = customtkinter.CTkImage(light_image=new_image, dark_image=new_image, size=(200, 100))

    # If there is an existing image, update its image
    if current_image_tag:
        current_image_tag.configure(image=new_ctk_image)
    # Otherwise, create a new CTkLabel with the new image
    else:
        global add_tag_window
        current_image_tag = customtkinter.CTkLabel(add_tag_window, text="", image=new_ctk_image)
        current_image_tag.pack(pady=10)

    image_path_ui_tag = tag_file_path


def add_tag_ui():
    global current_image_tag, image_path_ui_tag

    # Retrieve the text from text_1
    tag_text = text_3.get("1.0", "end").strip()

    # Retrieve the image path from the global variable
    if image_path_ui_tag:
        # Perform the embedding operation here
        add_text_exif(image_path_ui_tag, tag_text)

        print("Text to add to Tag:", tag_text)
        print("Image path:", image_path_ui_tag)

        show_message("Image saved as image_with_text" + os.path.splitext(str(image_path_ui_tag))[1])

        # print("Decoded text:")
        # print(binary_string_to_text(decode_text("modified_image.png")))

        # Clear the text in the textbox
        text_3.delete("1.0", "end")

        # Remove the displayed image
        if current_image_tag:
            current_image_tag.destroy()
            current_image_tag = None
        image_path_ui_tag = None
    else:
        print("No image selected.")
        show_error("No image selected.")


# For testing purposes
def print_test():
    print("test")


current_image = None


def display_image(file_path):
    global current_image
    global image_path_ui

    print(file_path)

    # Open the new image
    new_image = Image.open(file_path)
    new_image.thumbnail((200, 100))  # Resize the image if needed

    # Create a CTkImage from the new image
    new_ctk_image = customtkinter.CTkImage(light_image=new_image, dark_image=new_image, size=(200, 100))

    # If there is an existing image, update its image
    if current_image:
        current_image.configure(image=new_ctk_image)
    # Otherwise, create a new CTkLabel with the new image
    else:
        global pixel_window
        current_image = customtkinter.CTkLabel(pixel_window, text="", image=new_ctk_image)
        current_image.pack(pady=10)

    image_path_ui = file_path


# For testing purposes
def generate_random_text(length):
    rand_text = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))
    return rand_text


def embed_text_test():
    global current_image, image_path_ui

    # Retrieve the text from text_1
    text_to_embed = text_1.get("1.0", "end").strip()

    # Retrieve the image path from the global variable
    if image_path_ui:
        # Perform the embedding operation here
        result = embed_text(image_path_ui, text_to_embed)

        print("Text to embed:", text_to_embed)
        print("Image path:", image_path_ui)

        if result is not None:
            show_message("Image saved as modified_image.png")

        # print("Decoded text:")
        # print(binary_string_to_text(decode_text("modified_image.png")))

        # Clear the text in the textbox
        text_1.delete("1.0", "end")

        # Remove the displayed image
        if current_image:
            current_image.destroy()
            current_image = None
        image_path_ui = None
    else:
        print("No image selected.")
        show_error("No image selected.")


image_path_ui = None


def show_error(error_message):
    error_window = customtkinter.CTkToplevel()
    error_window.title("Error")
    error_window.geometry("450x100")
    error_window.grab_set()
    error_label = customtkinter.CTkLabel(master=error_window, text=error_message, justify=customtkinter.LEFT)
    error_label.pack()
    ok_button = customtkinter.CTkButton(master=error_window, text="Okay", command=error_window.destroy)
    ok_button.pack(pady=20, padx=10)
    play_sound("Resources/wrong-answer-129254.wav")


def show_message(text_message):
    message_window = customtkinter.CTkToplevel()
    message_window.title("Success")
    message_window.geometry("450x100")
    message_window.grab_set()
    message_label = customtkinter.CTkLabel(master=message_window, text=text_message, justify=customtkinter.LEFT)
    message_label.pack()
    ok_button = customtkinter.CTkButton(master=message_window, text="Okay", command=message_window.destroy)
    ok_button.pack(pady=20, padx=10)
    play_sound("Resources/level-up-191997.wav")


def play_sound(sound_file):
    # Load the sound file
    wave_obj = sa.WaveObject.from_wave_file(sound_file)

    # Play the sound asynchronously
    wave_obj.play()


def change_appearance_mode_event(new_appearance_mode):
    customtkinter.set_appearance_mode(new_appearance_mode)


def change_color_event(new_color):
    customtkinter.set_default_color_theme(new_color)
    print(new_color)


def open_wikipedia_page():
    try:
        url = f"https://en.wikipedia.org/wiki/Steganography"
        webbrowser.open(url)
    except Exception as e:
        print(f"An error occurred: {e}")


# # Example usage
# hidden_text = "ThatŽs what we a"
#
# random_text = generate_random_text(200)
#
# with open("initial_text.txt", "w") as file:
#     # Write some text to the file
#     file.write(random_text)
#
# #print(random_text)
#
# hidden_text = random_text
#
# # Embed the text in the image
# original_image_path = "cadnav-1F510004608.jpg"
#
# #green_pixel_values = get_initial_green_values(original_image_path)
#
# #print("green values Before:", green_pixel_values)
# #print("Last Green Value BEFORE:", green_pixel_values[-1])
#
# #print("binary data:", hidden_text)
#
# green_pixel_values = embed_text(original_image_path, hidden_text)
#
# #print("green values After:", green_pixel_values)
# #print("Last Green Value AFTER:", green_pixel_values[-1])
#
# # Decode Image Text
#
# decoded_binary = decode_text("test_modified_image.png")
#
# #print("Decoded binary:", decoded_binary)
#
# #print("Decoded text:", binary_string_to_text(decoded_binary))
#
# with open("decoded_text.txt", "w") as file:
#     # Write some text to the file
#     file.write(binary_string_to_text(decoded_binary))
#
# add_text_exif("demons.png", "CustomTag")
#
# tag_name = "CustomTag"
# extract_text_exif("image_with_text.png")
# # if tag_value is not None:
# #     print(f"Value of {tag_name}: {tag_value}")
# # else:
# #     print(f"No {tag_name} found in EXIF data.")


customtkinter.set_ctk_parent_class(tkinter.Tk)

customtkinter.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("dark-blue")  # Themes: "blue" (standard), "green", "dark-blue"

# App Root
app = customtkinter.CTk()
app.geometry("1050x600")
app.title("Steganography Tools")
app.resizable(False, False)

print(type(app), isinstance(app, tkinter.Tk))

play_sound("Resources/logo-corporate-152477.wav")

# Text Embed Window
pixel_window = customtkinter.CTkToplevel()
pixel_window.geometry("450x550")
pixel_window.title("Pixel Edit: Embed Text")
pixel_window.resizable(False, False)
pixel_window.withdraw()
pixel_window.protocol("WM_DELETE_WINDOW", pixel_window.withdraw)

pixel_button_1 = customtkinter.CTkButton(master=pixel_window, text="Select Image", command=open_file)
pixel_button_1.pack(pady=50, padx=10)

pixel_frame = customtkinter.CTkFrame(master=pixel_window)
pixel_frame.pack(side="bottom", pady=10, padx=10, fill="both", expand=False)

pixel_button_2 = customtkinter.CTkButton(master=pixel_frame, text="Embed the Text", command=embed_text_test)
pixel_button_2.pack(pady=50, padx=10)

pixel_frame_2 = customtkinter.CTkFrame(master=pixel_window)
pixel_frame_2.pack(side="bottom", pady=10, padx=10, fill="both", expand=False)

text_1 = customtkinter.CTkTextbox(master=pixel_frame_2, width=300, height=100)
text_1.pack(pady=10, padx=10)
text_1.insert("0.0", "Insert text to embed here...")

# Text Decode Window
decode_window = customtkinter.CTkToplevel()
decode_window.geometry("400x450")
decode_window.title("Pixel Edit: Decode Text")
decode_window.resizable(False, False)
decode_window.withdraw()
decode_window.protocol("WM_DELETE_WINDOW", decode_window.withdraw)

decode_button_1 = customtkinter.CTkButton(master=decode_window, text="Select Image", command=open_file_for_decoding)
decode_button_1.pack(pady=40, padx=10)

decode_progress_frame = customtkinter.CTkFrame(master=decode_window)
decode_progress_frame.pack(pady=10, padx=10, fill="both", expand=True)

decode_frame = customtkinter.CTkFrame(master=decode_window)
decode_frame.pack(pady=10, padx=10, fill="both", expand=True)

decode_progress_label = customtkinter.CTkLabel(master=decode_progress_frame, text="Decoding Progress:",
                                               justify=customtkinter.LEFT)

decode_progress_label.pack(pady=10, padx=10)

decode_progressbar = customtkinter.CTkProgressBar(master=decode_progress_frame)
decode_progressbar.pack(side="top", pady=10, padx=10)
decode_progressbar.set(0)

text_2 = customtkinter.CTkTextbox(master=decode_frame, width=300, height=300)
text_2.pack(pady=10, padx=10)
text_2.insert("0.0", "Decoded text will appear here...")

# Add EXIF Tag window
add_tag_window = customtkinter.CTkToplevel()
add_tag_window.geometry("450x550")
add_tag_window.title("Add EXIF Tag")
add_tag_window.resizable(False, False)
add_tag_window.withdraw()
add_tag_window.protocol("WM_DELETE_WINDOW", add_tag_window.withdraw)

add_tag_button = customtkinter.CTkButton(master=add_tag_window, text="Select Image", command=open_file_to_add_tag)
add_tag_button.pack(pady=50, padx=10)

add_tag_frame = customtkinter.CTkFrame(master=add_tag_window)
add_tag_frame.pack(side="bottom", pady=10, padx=10, fill="both", expand=False)

add_tag_button_2 = customtkinter.CTkButton(master=add_tag_frame, text="Add the Tag", command=add_tag_ui)
add_tag_button_2.pack(pady=50, padx=10)

add_tag_frame_2 = customtkinter.CTkFrame(master=add_tag_window)
add_tag_frame_2.pack(side="bottom", pady=10, padx=10, fill="both", expand=False)

text_3 = customtkinter.CTkTextbox(master=add_tag_frame_2, width=300, height=100)
text_3.pack(pady=10, padx=10)
text_3.insert("0.0", "Enter text to add to 0th ('make') EXIF tag...")

# Inspect EXIF Tags Window
inspect_tags_window = customtkinter.CTkToplevel()
inspect_tags_window.geometry("400x400")
inspect_tags_window.title("Inspect EXIF Tags")
inspect_tags_window.resizable(False, False)
inspect_tags_window.withdraw()
inspect_tags_window.protocol("WM_DELETE_WINDOW", inspect_tags_window.withdraw)

inspect_tags_button = customtkinter.CTkButton(master=inspect_tags_window, text="Select Image",
                                              command=open_file_to_see_tags)
inspect_tags_button.pack(pady=50, padx=10)

inspect_frame = customtkinter.CTkFrame(master=inspect_tags_window)
inspect_frame.pack(pady=10, padx=10, fill="both", expand=True)

text_4 = customtkinter.CTkTextbox(master=inspect_frame, width=300, height=300)
text_4.pack(pady=10, padx=10)
text_4.insert("0.0", "EXIF tags will appear here...")

# Audio encode window
encode_audio_window = customtkinter.CTkToplevel()
encode_audio_window.geometry("450x500")
encode_audio_window.title("Embed text in audio")
encode_audio_window.resizable(False, False)
encode_audio_window.withdraw()
encode_audio_window.protocol("WM_DELETE_WINDOW", encode_audio_window.withdraw)

embed_audio_button = customtkinter.CTkButton(master=encode_audio_window, text="Select WAV / MP3 file",
                                             command=open_file_to_see_audio)

embed_audio_button.pack(pady=10, padx=10)

embed_audio_label = customtkinter.CTkLabel(master=encode_audio_window, text="Selected file:",
                                           justify=customtkinter.LEFT)
embed_audio_label.pack(pady=10, padx=10)

embed_audio_label2 = customtkinter.CTkLabel(master=encode_audio_window, text="-",
                                            justify=customtkinter.LEFT)
embed_audio_label2.pack(pady=10, padx=10)

embed_audio_frame = customtkinter.CTkFrame(master=encode_audio_window, height=250)
embed_audio_frame.pack(side="top", pady=10, padx=10, fill="x", expand=False)

audio_text_to_embed = customtkinter.CTkTextbox(master=embed_audio_frame, width=300, height=250)
audio_text_to_embed.pack(pady=10, padx=10)
audio_text_to_embed.insert("0.0", "Enter text to add to audio file...")

audio_embed_text_button = customtkinter.CTkButton(master=encode_audio_window, text="Embed the Text",
                                                  command=add_text_to_audio_ui)
audio_embed_text_button.pack(pady=10, padx=10)

# Audio decode window
audio_decode_window = customtkinter.CTkToplevel()
audio_decode_window.geometry("450x500")
audio_decode_window.title("Decode text from audio")
audio_decode_window.resizable(False, False)
audio_decode_window.withdraw()
audio_decode_window.protocol("WM_DELETE_WINDOW", audio_decode_window.withdraw)


audio_decode_button = customtkinter.CTkButton(master=audio_decode_window, text="Select Audio File",
                                              command=open_audio_to_see_text_ui)

audio_decode_button.pack(pady=50, padx=10)

audio_decode_frame = customtkinter.CTkFrame(master=audio_decode_window)
audio_decode_frame.pack(pady=10, padx=10, fill="both", expand=True)

audio_decode_text = customtkinter.CTkTextbox(master=audio_decode_frame, width=300, height=300)
audio_decode_text.pack(pady=10, padx=10)
audio_decode_text.insert("0.0", "Embedded text will appear here...")

# PDF Metadata encode window
PDF_add_tag_window = customtkinter.CTkToplevel()
PDF_add_tag_window.geometry("450x650")
PDF_add_tag_window.title("Add Custom Tag and Text to PDF")
PDF_add_tag_window.resizable(False, False)
PDF_add_tag_window.withdraw()
PDF_add_tag_window.protocol("WM_DELETE_WINDOW", PDF_add_tag_window.withdraw)

PDF_add_tag_button = customtkinter.CTkButton(master=PDF_add_tag_window, text="Select PDF File",
                                             command=open_pdf_file_to_add_tag)
PDF_add_tag_button.pack(pady=20, padx=10)

PDF_label = customtkinter.CTkLabel(master=PDF_add_tag_window, text="Selected file:",
                                   justify=customtkinter.LEFT)
PDF_label.pack(pady=10, padx=10)

PDF_label2 = customtkinter.CTkLabel(master=PDF_add_tag_window, text="-",
                                    justify=customtkinter.LEFT)
PDF_label2.pack(pady=10, padx=10)

PDF_frame = customtkinter.CTkFrame(master=PDF_add_tag_window, height=250)
PDF_frame.pack(side="top", pady=10, padx=10, fill="both", expand=False)

PDF_tag_name = customtkinter.CTkTextbox(master=PDF_frame, width=300, height=50)
PDF_tag_name.pack(pady=10, padx=10)
PDF_tag_name.insert("0.0", "Enter tag name...")

PDF_frame2 = customtkinter.CTkFrame(master=PDF_add_tag_window, height=250)
PDF_frame2.pack(side="top", pady=10, padx=10, fill="both", expand=False)

PDF_text_to_embed = customtkinter.CTkTextbox(master=PDF_frame2, width=300, height=250)
PDF_text_to_embed.pack(pady=10, padx=10)
PDF_text_to_embed.insert("0.0", "Enter text to add to PDF file metadata tag...")

PDF_tag_process_button = customtkinter.CTkButton(master=PDF_add_tag_window, text="Add Tag with Text",
                                                 command=add_pdf_tag_ui)

PDF_tag_process_button.pack(pady=10, padx=10)

# PDF Decode Window
PDF_decode_window = customtkinter.CTkToplevel()
PDF_decode_window.geometry("450x500")
PDF_decode_window.title("See PDF tags")
PDF_decode_window.resizable(False, False)
PDF_decode_window.withdraw()
PDF_decode_window.protocol("WM_DELETE_WINDOW", PDF_decode_window.withdraw)

PDF_decode_button = customtkinter.CTkButton(master=PDF_decode_window, text="Select PDF File",
                                            command=open_pdf_to_see_tags_ui)

PDF_decode_button.pack(pady=50, padx=10)

PDF_decode_frame = customtkinter.CTkFrame(master=PDF_decode_window)
PDF_decode_frame.pack(pady=10, padx=10, fill="both", expand=True)

PDF_decode_text = customtkinter.CTkTextbox(master=PDF_decode_frame, width=300, height=300)
PDF_decode_text.pack(pady=10, padx=10)
PDF_decode_text.insert("0.0", "Tags will appear here...")

# Video Add Metadata Window
video_add_metadata_window = customtkinter.CTkToplevel()
video_add_metadata_window.geometry("450x650")
video_add_metadata_window.title("Embed text in audio")
video_add_metadata_window.resizable(False, False)
video_add_metadata_window.withdraw()
video_add_metadata_window.protocol("WM_DELETE_WINDOW", video_add_metadata_window.withdraw)

video_add_metadata_button = customtkinter.CTkButton(master=video_add_metadata_window, text="Select Video File",
                                                    command=open_video_to_add_tag)
video_add_metadata_button.pack(pady=20, padx=10)

video_add_metadata_label = customtkinter.CTkLabel(master=video_add_metadata_window, text="Selected file:",
                                                  justify=customtkinter.LEFT)
video_add_metadata_label.pack(pady=10, padx=10)

video_add_metadata_label2 = customtkinter.CTkLabel(master=video_add_metadata_window, text="-",
                                                   justify=customtkinter.LEFT)
video_add_metadata_label2.pack(pady=10, padx=10)

video_add_metadata_label3 = customtkinter.CTkLabel(master=video_add_metadata_window, text="Choose tag to add text to:",
                                                   justify=customtkinter.LEFT)
video_add_metadata_label3.pack(pady=10, padx=10)

video_metadata_tag_option_menu = customtkinter.CTkOptionMenu(video_add_metadata_window,
                                                             values=["Comment", "Genre", "Title", "Description"],
                                                             command=change_video_tag_event)
video_metadata_tag_option_menu.pack(pady=10, padx=10)

video_add_metadata_frame = customtkinter.CTkFrame(master=video_add_metadata_window, height=275)
video_add_metadata_frame.pack(side="top", pady=10, padx=10, fill="both", expand=False)

video_add_metadata_text = customtkinter.CTkTextbox(master=video_add_metadata_frame, width=375, height=250)
video_add_metadata_text.pack(pady=10, padx=10)
video_add_metadata_text.insert("0.0", "Enter text to add to video file metadata tag...")

video_add_metadata_process_button = customtkinter.CTkButton(master=video_add_metadata_window, text="Add Tag with Text",
                                                            command=add_video_tag_ui)

video_add_metadata_process_button.pack(pady=10, padx=10)

# Video See Metadata Window
video_see_metadata_window = customtkinter.CTkToplevel()
video_see_metadata_window.geometry("450x500")
video_see_metadata_window.title("See Video metadata tags")
video_see_metadata_window.resizable(False, False)
video_see_metadata_window.withdraw()
video_see_metadata_window.protocol("WM_DELETE_WINDOW", video_see_metadata_window.withdraw)

video_see_metadata_button = customtkinter.CTkButton(master=video_see_metadata_window, text="Select Video File",
                                                    command=open_video_to_see_tags_ui)

video_see_metadata_button.pack(pady=50, padx=10)

video_see_metadata_frame = customtkinter.CTkFrame(master=video_see_metadata_window)
video_see_metadata_frame.pack(pady=10, padx=10, fill="both", expand=True)

video_see_metadata_text = customtkinter.CTkTextbox(master=video_see_metadata_frame, width=300, height=300)
video_see_metadata_text.pack(pady=10, padx=10)
video_see_metadata_text.insert("0.0", "Tags will appear here...")

# Base64 window
base64_window = customtkinter.CTkToplevel()
base64_window.geometry("550x600")
base64_window.title("Base64")
base64_window.resizable(False, False)
base64_window.withdraw()
base64_window.protocol("WM_DELETE_WINDOW", base64_window.withdraw)

base64_frame1 = customtkinter.CTkFrame(master=base64_window, corner_radius=0)
base64_frame1.pack(side="top", pady=10, padx=10, fill="both", expand=True)

base64_frame3 = customtkinter.CTkFrame(master=base64_window, corner_radius=0, height=50)
base64_frame3.pack(side="bottom", pady=10, padx=10, fill="both", expand=True)

base64_frame2 = customtkinter.CTkFrame(master=base64_window, corner_radius=0)
base64_frame2.pack(side="bottom", pady=10, padx=10, fill="both", expand=True)

base64_frame4 = customtkinter.CTkFrame(master=base64_frame3, corner_radius=0, height=5)
base64_frame4.pack(side="left", pady=10, padx=10, fill="both", expand=True)

base64_frame5 = customtkinter.CTkFrame(master=base64_frame3, corner_radius=0, height=5)
base64_frame5.pack(side="right", pady=10, padx=10, fill="both", expand=True)

base64_button = customtkinter.CTkButton(master=base64_frame4, text="Encode Text",
                                        command=encode_base64_ui)
base64_button.pack(pady=25, padx=0)

base64_button2 = customtkinter.CTkButton(master=base64_frame5, text="Swap",
                                         command=base64_swap_event)
base64_button2.pack(pady=25, padx=0)

base64_textbox = customtkinter.CTkTextbox(master=base64_frame1, width=500)
base64_textbox.pack(pady=10, padx=10)
base64_textbox.insert("0.0", "Enter text to encode in Base64...")

base64_textbox2 = customtkinter.CTkTextbox(master=base64_frame2, width=500)
base64_textbox2.pack(pady=10, padx=10)
base64_textbox2.insert("0.0", "Encoded text will appear here...")

# AES Window
aes_window = customtkinter.CTkToplevel()
aes_window.geometry("550x675")
aes_window.title("Base64")
aes_window.resizable(False, False)
aes_window.withdraw()
aes_window.protocol("WM_DELETE_WINDOW", aes_window.withdraw)

aes_frame6 = customtkinter.CTkFrame(master=aes_window, corner_radius=0)
aes_frame6.pack(side="top", pady=10, padx=10, fill="both", expand=True)

aes_frame7 = customtkinter.CTkFrame(master=aes_window, corner_radius=0)
aes_frame7.pack(side="top", pady=10, padx=10, fill="both", expand=False)

aes_textbox3 = customtkinter.CTkTextbox(master=aes_frame7, width=500, height=25)
aes_textbox3.pack(pady=10, padx=10)
aes_textbox3.insert("0.0", "Replace this text with the Key in hexadecimal (32/48/64 digits)")

aes_frame1 = customtkinter.CTkFrame(master=aes_window, corner_radius=0)
aes_frame1.pack(side="top", pady=10, padx=10, fill="both", expand=True)

aes_frame3 = customtkinter.CTkFrame(master=aes_window, corner_radius=0, height=50)
aes_frame3.pack(side="bottom", pady=10, padx=10, fill="both", expand=True)

aes_frame2 = customtkinter.CTkFrame(master=aes_window, corner_radius=0)
aes_frame2.pack(side="bottom", pady=10, padx=10, fill="both", expand=True)

aes_frame4 = customtkinter.CTkFrame(master=aes_frame3, corner_radius=0, height=5)
aes_frame4.pack(side="left", pady=10, padx=10, fill="both", expand=True)

aes_frame5 = customtkinter.CTkFrame(master=aes_frame3, corner_radius=0, height=5)
aes_frame5.pack(side="right", pady=10, padx=10, fill="both", expand=True)

aes_button = customtkinter.CTkButton(master=aes_frame4, text="Encrypt Text",
                                     command=encrypt_aes_ui)
aes_button.pack(pady=25, padx=0)

aes_button2 = customtkinter.CTkButton(master=aes_frame5, text="Swap",
                                      command=aes_swap_event)
aes_button2.pack(pady=25, padx=0)

aes_textbox = customtkinter.CTkTextbox(master=aes_frame1, width=500, height=150)
aes_textbox.pack(pady=10, padx=10)
aes_textbox.insert("0.0", "Enter text to encrypt with AES...")

aes_textbox2 = customtkinter.CTkTextbox(master=aes_frame2, width=500)
aes_textbox2.pack(pady=10, padx=10)
aes_textbox2.insert("0.0", "Encrypted text will appear here...")

video_label = customtkinter.CTkLabel(aes_frame6, text="Select AES Encryption mode:")
video_label.pack(side="top", padx=0, pady=0)

aes_mode_option_menu = customtkinter.CTkOptionMenu(aes_frame6, values=["ECB", "CBC", "CFB", "OFB"],
                                                   command=change_aes_option_event)
aes_mode_option_menu.pack(side="bottom", pady=10, padx=10)


# Additionals Window
additional_window = customtkinter.CTkToplevel()
additional_window.geometry("600x400")
additional_window.title("Additional Tools")
additional_window.resizable(False, False)
additional_window.withdraw()
additional_window.protocol("WM_DELETE_WINDOW", additional_window.withdraw)

additional_frame = customtkinter.CTkFrame(master=additional_window, corner_radius=0)
additional_frame.pack(pady=10, padx=10, fill="both", expand=True)

video_frame = customtkinter.CTkFrame(master=additional_frame)
video_frame.pack(side="left", pady=10, padx=10, fill="both", expand=True)

video_label = customtkinter.CTkLabel(video_frame, text="Video Operations:",
                                     font=customtkinter.CTkFont(weight="bold"))
video_label.pack(side="top", padx=10, pady=10)

video_frame1 = customtkinter.CTkFrame(master=video_frame)
video_frame1.pack(side="left", pady=10, padx=10, fill="both", expand=True)

# video_frame2 = customtkinter.CTkFrame(master=video_frame)
# video_frame2.pack(side="right", pady=10, padx=10, fill="both", expand=True)

video_button = customtkinter.CTkButton(master=video_frame1, text="Add text to metadata tag",
                                       command=video_add_metadata_window.deiconify)
video_button.pack(pady=30, padx=30)

video_button2 = customtkinter.CTkButton(master=video_frame1, text="See metadata tags",
                                        command=video_see_metadata_window.deiconify)
video_button2.pack(pady=30, padx=30)

video_button3 = customtkinter.CTkButton(master=video_frame1, text="Extract video audio",
                                        command=open_video_file_to_extract_audio)
video_button3.pack(pady=30, padx=30)

crypto_frame = customtkinter.CTkFrame(master=additional_frame)
crypto_frame.pack(side="right", pady=10, padx=10, fill="both", expand=True)

crypto_frame1 = customtkinter.CTkFrame(master=crypto_frame)
crypto_frame1.pack(side="bottom", pady=10, padx=10, fill="both", expand=True)

crypto_label = customtkinter.CTkLabel(crypto_frame, text="Crypto tools:",
                                      font=customtkinter.CTkFont(weight="bold"))
crypto_label.pack(side="top", padx=30, pady=10)

crypto_button = customtkinter.CTkButton(master=crypto_frame1, text="Base64",
                                        command=base64_window.deiconify)
crypto_button.pack(pady=30, padx=30)

crypto_button2 = customtkinter.CTkButton(master=crypto_frame1, text="AES",
                                         command=aes_window.deiconify)
crypto_button2.pack(pady=30, padx=30)


# Root of GUI
info_frame = customtkinter.CTkFrame(master=app, width=140, corner_radius=0)
info_frame.pack(side="left", pady=10, padx=10, fill="both", expand=True)

appearance_mode_option_menu = customtkinter.CTkOptionMenu(info_frame, values=["System", "Light", "Dark"],
                                                          command=change_appearance_mode_event)
appearance_mode_option_menu.pack(side="bottom", pady=10, padx=10)

appearance_mode_label = customtkinter.CTkLabel(info_frame, text="Appearance Mode:", anchor="w")
appearance_mode_label.pack(side="bottom", padx=5, pady=5)

logo_label = customtkinter.CTkLabel(info_frame, text="Steganography File Tools",
                                    font=customtkinter.CTkFont(size=20, weight="bold"))
logo_label.pack(pady=10, padx=10)

# info_text = customtkinter.CTkTextbox(master=info_frame, width=200, height=250, wrap="word")
# info_text.pack(pady=10, padx=10)
# info_text.insert("0.0",
#                  "This is a collection of useful tools with the purpose of hiding information inside files, "
#                  "as well as the means of retrieving said information.\n\n"
#                  "If you would like to know more about the process of steganography and what it entails, "
#                  "you can click on the button below.")
# info_text.configure(state="disabled")

logo_image = Image.open("Resources/Screenshot 2024-04-27 231346.png")
logo_image.thumbnail((175, 115))
ctk_logo_image = customtkinter.CTkImage(light_image=logo_image, dark_image=logo_image, size=(175, 115))
current_logo_image = customtkinter.CTkLabel(info_frame, text="", image=ctk_logo_image)
current_logo_image.pack(pady=10)

button_7 = customtkinter.CTkButton(master=info_frame, text="What is this?", command=open_wikipedia_page)
button_7.pack(pady=10, padx=10)

additionals_button = customtkinter.CTkButton(master=info_frame, text="Additionals", command=additional_window.deiconify)
additionals_button.pack(side="bottom", pady=10, padx=10)

additionals_label = customtkinter.CTkLabel(info_frame, text="Additional Tools:", anchor="w")
additionals_label.pack(side="bottom", padx=5, pady=5)

message_frame_1 = customtkinter.CTkFrame(master=app)
message_frame_1.pack(side="top", pady=10, padx=10, fill="x", expand=False)

label_1 = customtkinter.CTkLabel(master=message_frame_1, text="Choose desired operation for an image:",
                                 justify=customtkinter.LEFT, font=customtkinter.CTkFont(weight="bold"))
label_1.pack(pady=10, padx=10)


frame_1 = customtkinter.CTkFrame(master=message_frame_1)
frame_1.pack(side="left", pady=10, padx=10, fill="x", expand=False)

frame_2 = customtkinter.CTkFrame(master=message_frame_1)
frame_2.pack(side="right", pady=10, padx=10, fill="x", expand=False)

frame_3 = customtkinter.CTkFrame(master=app, width=200, height=200)
frame_3.pack(side="left", pady=10, padx=10, fill="y", expand=False)

frame_4 = customtkinter.CTkFrame(master=frame_3, width=200, height=200)
frame_4.pack(side="bottom", pady=10, padx=10, fill="y", expand=True)

label_4 = customtkinter.CTkLabel(master=frame_3, text="Choose desired operation for an audio file:",
                                 justify=customtkinter.LEFT, font=customtkinter.CTkFont(weight="bold"))

label_4.pack(pady=10, padx=10)

button_5 = customtkinter.CTkButton(master=frame_4, text="Add text to the audio", command=encode_audio_window.deiconify)
button_5.pack(pady=30, padx=100)

button_6 = customtkinter.CTkButton(master=frame_4, text="Decode text from audio",
                                   command=audio_decode_window.deiconify)
button_6.pack(pady=10, padx=100)

frame_5 = customtkinter.CTkFrame(master=app)
frame_5.pack(side="left", pady=10, padx=10, fill="both", expand=True)

frame_6 = customtkinter.CTkFrame(master=frame_5, width=200, height=200)
frame_6.pack(side="bottom", pady=10, padx=10, fill="y", expand=True)

label_5 = customtkinter.CTkLabel(master=frame_5, text="Choose desired operation for a PDF file:",
                                 justify=customtkinter.LEFT, font=customtkinter.CTkFont(weight="bold"))
label_5.pack(pady=10, padx=10)

button_8 = customtkinter.CTkButton(master=frame_6, text="Add text to metadata custom tag",
                                   command=PDF_add_tag_window.deiconify)
button_8.pack(pady=30, padx=60)

button_9 = customtkinter.CTkButton(master=frame_6, text="Decode text from metadata",
                                   command=PDF_decode_window.deiconify)
button_9.pack(pady=10, padx=10)

label_2 = customtkinter.CTkLabel(master=frame_1, text="Pixel Operations", justify=customtkinter.LEFT)
label_2.pack(pady=20, padx=10)

label_3 = customtkinter.CTkLabel(master=frame_2, text="Metadata Operations", justify=customtkinter.LEFT)
label_3.pack(pady=20, padx=10)

button_1 = customtkinter.CTkButton(master=frame_1, text="Embed Text in Image", command=pixel_window.deiconify)
button_1.pack(pady=20, padx=100)

button_2 = customtkinter.CTkButton(master=frame_1, text="Decode Text from Image", command=decode_window.deiconify)
button_2.pack(pady=20, padx=100)

button_3 = customtkinter.CTkButton(master=frame_2, text="Add Text to EXIF Tag", command=add_tag_window.deiconify)
button_3.pack(pady=20, padx=100)

button_4 = customtkinter.CTkButton(master=frame_2, text="See Image EXIF tags", command=inspect_tags_window.deiconify)
button_4.pack(pady=20, padx=100)

app.mainloop()
