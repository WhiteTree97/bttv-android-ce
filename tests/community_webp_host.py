"""Generate tests of the actual replacement Drawable and BTTV animation adapter.

Use the hash-verified decoder 2.7 classes.jar, Glide/GIF 4.12.0, and Robolectric.
Only frame loading is shadowed: no Android JNI is executed on the host JVM.
These tests do not replace physical-device animated-WebP decoding tests.
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    'bttv/glide/Webp.java': (ROOT/'mod/app/src/main/java/bttv/glide/Webp.java').read_text(),
    'com/bumptech/glide/integration/webp/decoder/WebpAnimationCompatibilityTest.java': r'''
package com.bumptech.glide.integration.webp.decoder;
import android.graphics.Bitmap;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import com.bumptech.glide.Glide;
import com.bumptech.glide.RequestBuilder;
import com.bumptech.glide.RequestManager;
import com.bumptech.glide.load.Transformation;
import com.bumptech.glide.load.engine.bitmap_recycle.BitmapPool;
import android.os.Handler;
import org.junit.*;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.*;
import org.robolectric.annotation.internal.DoNotInstrument;

@RunWith(RobolectricTestRunner.class)
@Config(sdk=30,manifest=Config.NONE,shadows={WebpAnimationCompatibilityTest.Frames.class},
 instrumentedPackages={"com.bumptech.glide.integration.webp.decoder"})
@DoNotInstrument
public class WebpAnimationCompatibilityTest {
 @Implements(value=WebpFrameLoader.class,isInAndroidSdk=false)
 @DoNotInstrument
 public static class Frames {
  static int subscribed,unsubscribed,cleared;
  @Implementation protected void __constructor__(BitmapPool pool,RequestManager manager,
      WebpDecoder decoder,Handler handler,RequestBuilder<Bitmap> request,
      Transformation<Bitmap> transform,Bitmap first) {}
  @Implementation protected int getFrameCount(){return 2;}
  @Implementation protected int getLoopCount(){return 0;}
  @Implementation protected int getCurrentIndex(){return 1;}
  @Implementation protected int getWidth(){return 20;}
  @Implementation protected int getHeight(){return 10;}
  @Implementation protected void subscribe(WebpFrameLoader.FrameCallback callback){subscribed++;}
  @Implementation protected void unsubscribe(WebpFrameLoader.FrameCallback callback){unsubscribed++;}
  @Implementation protected void clear(){cleared++;}
 }
 static class Callback implements Drawable.Callback {
  int invalidated;
  public void invalidateDrawable(Drawable d){invalidated++;}
  public void scheduleDrawable(Drawable d,Runnable r,long when){}
  public void unscheduleDrawable(Drawable d,Runnable r){}
 }
 @Before public void reset(){Frames.subscribed=Frames.unsubscribed=Frames.cleared=0;}
 WebpDrawable drawable(){return new WebpDrawable(new WebpFrameLoader(null,null,null,null,null,null,null),null,new Paint());}
 @Test public void actualAdapterStartsOnceInvalidatesAndStopsWithoutResizing(){
  WebpDrawable d=drawable();Callback c=new Callback();d.setBounds(0,0,20,10);Rect before=new Rect(d.getBounds());
  bttv.glide.Webp.setWebpCallback(d,c);bttv.glide.Webp.startWebpDrawable(d);bttv.glide.Webp.startWebpDrawable(d);
  assertTrue(d.isRunning());assertEquals(1,Frames.subscribed);assertSame(c,d.getCallback());
  int n=c.invalidated;d.onFrameReady();assertTrue(c.invalidated>n);assertTrue(d.isRunning());
  bttv.glide.Webp.stopWebpDrawable(d);assertFalse(d.isRunning());assertEquals(1,Frames.unsubscribed);
  assertEquals(before,d.getBounds());assertEquals(20,d.getIntrinsicWidth());assertEquals(10,d.getIntrinsicHeight());
 }
 @Test public void removedCallbackStopsAnimationAndVisibilityCanPauseResume(){
  WebpDrawable d=drawable();Callback c=new Callback();bttv.glide.Webp.setWebpCallback(d,c);
  bttv.glide.Webp.startWebpDrawable(d);d.setVisible(false,false);assertFalse(d.isRunning());
  d.setVisible(true,false);assertTrue(d.isRunning());assertEquals(2,Frames.subscribed);
  bttv.glide.Webp.setWebpCallback(d,null);d.onFrameReady();assertFalse(d.isRunning());assertNull(d.getCallback());
 }
 @Test public void recyclingClearsLoaderAndRefusesRestart(){
  WebpDrawable d=drawable();bttv.glide.Webp.setWebpCallback(d,new Callback());
  bttv.glide.Webp.startWebpDrawable(d);bttv.glide.Webp.stopWebpDrawable(d);d.recycle();
  assertEquals(1,Frames.cleared);
  try{bttv.glide.Webp.startWebpDrawable(d);fail("Recycled drawable restarted");}
  catch(IllegalArgumentException expected){}
 }
}
'''
}

if __name__ == '__main__':
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=False)
    for name, source in SOURCES.items():
        target = out/name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding='utf-8')
