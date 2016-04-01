/**
 * Created by Lukas on 29-Mar-16.
 */
public class ValueHolder {
    private short LP; // huidige LP op kaart
    private short amount; // hoeveel je wilt toevoegen/verwijderen
    private boolean legit;

    public ValueHolder() {
        LP = 0;
        amount = 0;
        legit = false;
    }

    // Houdt geen rekening met over- en underflow (schoolproject..)
    public boolean setLPToAdd(short toAdd) {
        if (LP + toAdd < 0) {
            legit = false;
            return false;
        }
        else {
            amount = toAdd;
            legit = true;
            return true;
        }
    }

    public void setLP(short LP) {
        this.LP = LP;
    }

    public short getLP() {
        return LP;
    }

    public short getAmount() {
        return amount;
    }

    public boolean isLegit() {
        return legit;
    }
}
