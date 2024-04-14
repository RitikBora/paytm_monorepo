import { useRecoilValue } from "recoil"
import balanceAtom from "../atoms/balance";

const useBalance=  () =>
{
    const value = useRecoilValue(balanceAtom);
    return value;
}

export default useBalance;