import sounddevice as sd
import numpy as np
import soundfile as sf
import keyboard
import time
import threading
class Recorder:
        def callback(self, indata, frames, time, status):
            if status:
                print(f"Warning: {status}")
            self.recorded_frames.append(indata.copy())  # חשוב להעתיק את המידע כי הוא משתנה

        def Start_Recording(self):
            self.running = True
            self.recorded_frames = []
            self.stream = sd.InputStream(callback=self.callback, samplerate=44100, channels=1) 
            self.stream.start()   
            while self.running:
                time.sleep(0.01)
               

        def End_Recording(self):
            self.running = False
            time.sleep(0.3) #אמור למנוע הפסקה של הסטרים לפני סיום השמירה של הפריימים האחרונים של האודיו בשביל שלא יחתך בסוף
            self.stream.stop()
            self.stream.close()
            while self.stream.active:
                time.sleep(0.01)
            self.full_audio_stream_numpy = np.concatenate(self.recorded_frames) # מחברים את כל הפריימים למערך אחד
            return self.Full_Audio_Stream_Numpy_To_Bytes_And_Return()

        def Full_Audio_Stream_Numpy_To_Bytes_And_Return(self):
            full_audio_stream_bytes = self.full_audio_stream_numpy.tobytes()
            return full_audio_stream_bytes