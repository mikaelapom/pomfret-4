
/*
 *   Copyright (C) 2019 -- 2024  Zachary A. Kissel
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
import java.util.Scanner;

import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.util.Tuple;

import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * This file implements a PKCS #7 padding attack on a CBC encrypted ciphertext.
 */
public class PaddingAttack {
  private static PaddingOracle oracle; // The padding oracle used in the attack.
  private static String ctxtFile = null; // The file containing the ciphertext to attack.
  private static String keyFile = null; // The file containing the oracle's key.

  /**
   * Print how to use the program and exit.
   */
  private static void usage() {
    System.out.println("usage:");
    System.out.println("  cbc-attack --key <keyfile> --ctxt <ciphertext file>");
    System.out.println("  cbc-attack --help");
    System.out.println("options:");
    System.out.println("  -k, --key\t\tSpecify the decryption key file for the oracle");
    System.out.println("  -c, --ctext\t\tSpecify the ciphertext file to attack.");
    System.out.println("  -h, --help\t\tDisplay this message.");
    System.exit(1);
  }

  /**
   * Processes the command line arugments.
   * 
   * @param args the command line arguments.
   */
  public static void processArgs(String[] args) { // for cmd line
    OptionParser parser;
    boolean doHelp = false;
    boolean doAttack = false;

    LongOption[] opts = new LongOption[3];
    opts[0] = new LongOption("help", false, 'h');
    opts[1] = new LongOption("key", true, 'k');
    opts[2] = new LongOption("ctxt", true, 'c');

    Tuple<Character, String> currOpt;

    parser = new OptionParser(args);
    parser.setLongOpts(opts);
    parser.setOptString("hc:k:");

    while (parser.getOptIdx() != args.length) {
      currOpt = parser.getLongOpt(false);

      switch (currOpt.getFirst()) {
        case 'h':
          doHelp = true;
          break;
        case 'c':
          doAttack = true;
          ctxtFile = currOpt.getSecond();
          break;
        case 'k':
          doAttack = true;
          keyFile = currOpt.getSecond();
          break;
        case '?':
          System.out.println("Unknown option: " + currOpt.getSecond());
          usage();
          break;
      }
    }

    // Verify that that this options are not conflicting.
    if ((doAttack && doHelp))
      usage();

    if (doHelp)
      usage();

    // verify that we have the files needed for the attack.
    if (keyFile == null) {
      System.out.println("Missing key file.");
      System.exit(1);
    }

    if (ctxtFile == null) {
      System.out.println("Missing ciphertext file to attack.");
      System.exit(1);
    }
  }

  /**
   * Given the padding oracle and the ciphertext blocks this works to recover the
   * plaintext message.
   * 
   * @param blocks the blocks of the ciphertext the first block is the
   *               IV.merrimackutil.json.parser.ast.nodes.SyntaxNode
   * @return the plaintext message, which we know is a string.
   */
  public static String recoverPlaintext(ArrayList<Block> blocks) {

    byte[] ptext = new byte[(blocks.size() - 1) * 16]; // this will hold plaintext that we build

    // i indicates which block you are on
    for (int i = 1; i < blocks.size(); i++) {
      Block cPrime = blocks.get(i); // this is current block
      Block c = blocks.get(i - 1); // this is previous block

      // byte[] T = c.toArray(); // modified c block
      byte[] T = new byte[16];
      byte[] decryption = new byte[16];

      // start from last byte
      for (int j = 15; j >= 0; j--) {
        byte padVal = (byte) (16 - j); // padding value (cant be more than the length)

        // modify T
        for (int k = 15; k > j; k--) {
          T[k] = (byte) (padVal ^ T[k] ^ decryption[k]);

        }

        // guess T against 256 possibilities
        for (int x = 0; x < 256; x++) {
          int guess = x;
          T[i] = (byte) guess;

          ArrayList<Block> TC = new ArrayList<>(blocks);
          TC.set(i - 1, new Block(T));

          if (oracle.decrypt(TC)) {
            decryption[j] = (byte) (c.getByte(j) ^ padVal ^ T[j]); // ptext byte stored in decryption array
            break;
            // ptext[j] = (byte) (guess ^ c.getByte(j) ^ padVal);
          }

        }

      }
      System.arraycopy(decryption, 0, ptext, (i - 1) * 16, 16);

    }
    return new String(ptext, StandardCharsets.UTF_8).trim(); // Convert byte array to String

    /*
     * StringBuilder plaintext = new StringBuilder();
     * for (byte i : ptext) {
     * plaintext.append((char) i);
     * }
     * 
     * return plaintext.toString();
     */

  }

  /**
   * The entrypoint for the application. This starts the attack.
   * 
   * @param args the command line arguments.
   * @throws FileNotFoundException if one of the files could not be found.
   */
  public static void main(String[] args) throws FileNotFoundException {
    String iv; // The IV read from the file.
    String ciphertext; // The ciphertext read from the file.

    processArgs(args);

    // Create the decryption oracle.
    try {
      oracle = new PaddingOracle(keyFile);
    } catch (FileNotFoundException e) {
      System.out.println(e);
      return;
    }

    // Read the ciphertext and IV from the file.
    File file = new File(ctxtFile);

    if (!file.exists()) {
      System.out.println("Ciphertext file does not exist!");
      return;
    }

    // Read the IV and ciphertext in.
    Scanner fileIn = new Scanner(file);
    iv = fileIn.nextLine();
    ciphertext = fileIn.nextLine();
    fileIn.close();

    // Display the resulting plaintext.
    System.out.println(recoverPlaintext(toBlocks(iv, ciphertext)));
  }

  /**
   * A helper method that takes a base64 encoded IV and ciphertext and constructs
   * an
   * array list of 16 byte AES blocks (byte[]s).
   * 
   * @param ivBase64         the base 64 encoded IV.
   * @param ciphertextBase64 the base 64 encoded ciphertext.
   * @return An array list of 16 byte AES blocks.
   */
  private static ArrayList<Block> toBlocks(String ivBase64, String ciphertextBase64) {
    ArrayList<Block> blocks = new ArrayList<>();
    byte[] iv = Base64.getDecoder().decode(ivBase64);
    byte[] ciphertext = Base64.getDecoder().decode(ciphertextBase64);

    // Build a list of blocks.
    blocks.add(new Block(iv));
    for (int i = 0; i < (ciphertext.length / 16); i++)
      blocks.add(new Block(Arrays.copyOfRange(ciphertext, i * 16, (i * 16) + 16)));

    return blocks;
  }
}
