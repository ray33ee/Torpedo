

#[cfg(test)]
mod macro_tests {

    use torserde_macros::Torserde;
    use torserde::{TorSerde, NLengthVector};
    use std::net::Ipv4Addr;

    #[derive(Torserde, PartialEq, Eq, Debug)]
    struct SimpleStruct {
        x: u32,
        y: u32,
    }

    #[derive(Torserde, PartialEq, Eq, Debug)]
    #[repr(u8)]
    enum SimpleEnum {
        First = 10,
        Second(u32, Ipv4Addr) = 11,
        Third(u128, String) = 12,
    }

    #[derive(Torserde, PartialEq, Eq, Debug)]
    struct InnerList {
        command: u8,
        list: NLengthVector<SimpleStruct, 1>,
    }

    #[derive(Torserde, PartialEq, Eq, Debug)]
    struct OuterList {
        command: u8,
        list: NLengthVector<InnerList, 1>,
    }

    #[test]
    fn nested_list() {
        let buff = vec![
            14,
            2,
                0,
                1,
                    0, 0, 0, 1,
                    0, 0, 0, 2,
                12,
                2,
                    0, 0, 0, 3,
                    0, 0, 0, 4,
                    0, 0, 0, 5,
                    0, 0, 0, 6];

        let outer = OuterList::bin_deserialise_from(buff.as_slice());

        println!("outer: {:?}", outer);
    }

    #[test]
    fn simple_struct_test() {
        let mut buf = Vec::new();

        let simple_struct = SimpleStruct{ x: 0xf2795e6d, y: 0x4e9237a7 };

        simple_struct.bin_serialise_into(& mut buf);

        assert_eq!(buf, vec![0xf2, 0x79, 0x5e, 0x6d, 0x4e, 0x92, 0x37, 0xa7]);

        let d_simple_struct = SimpleStruct::bin_deserialise_from(buf.as_slice());

        assert_eq!(simple_struct, d_simple_struct);



    }

}
