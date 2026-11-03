package bttv.updater;

import android.app.Activity;
import android.os.Bundle;

/** Legacy intents never trust URL extras or open an installer. Use the secure dialog. */
public class UpdaterActivity extends Activity {
    private UpdateDialog dialog;
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        dialog=new UpdateDialog(this,this::finish);
        dialog.show();
    }
    @Override protected void onDestroy() {
        if(dialog!=null)dialog.dispose();
        super.onDestroy();
    }
}
